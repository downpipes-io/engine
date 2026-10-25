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
#      Pass --break-glass-only to land in strict break-glass-only custody instead: no
#      operational key is generated, and the OPERATIONAL_RETIRED marker is installed so
#      the next deploy does not silently reverse the choice.
#      The CONFIG WRAP KEY is generated and installed here too, in both postures and on
#      an engine that predates it, so console-stored credentials (destinations, the SIEM
#      and notify integrations, the read-only Cloudflare discovery token) are encrypted
#      at rest in the Durable Object rather than sitting on the platform-encryption floor.
#   3. BOOTSTRAP_OWNER_EMAIL, prompted once when absent: the address the
#      first-Owner set-up link is emailed to (never a client-typed one).
#
# Everything else (the read-only discovery token, the archive destination,
# sources, downpipes) is set IN THE CONSOLE, guided step by step.
#
# BEFORE ANY OF THAT, a BLOCKING PREFLIGHT grades the tree this deploy is about to ship
# (installed dependencies, typecheck, the build, then the customer validate chain). It is the
# first thing that runs and it refuses on a failure and on a could-not-check alike. The argument
# for it, and for which gates it runs and which it leaves to `npm run validate`, is at the
# preflight itself below.
set -e
cd "$(dirname "$0")/.."; . ./scripts/node-floor.sh

# --enable-operational / --yes: the explicit override for B7. Without one of these, this script
# REFUSES to auto-generate an operational key when OPERATIONAL_RETIRED is set (the durable marker
# POST /keys/break-glass-only writes), so a routine redeploy can never silently reverse an owner's
# deliberate, confirm-gated switch to break-glass-only custody.
#
# --break-glass-only: the explicit OPPOSITE answer, for the FRESH-ENGINE branch below. Without one of
# the two flags, a fresh install on a TTY now ASKS which custody posture to install, and a fresh install
# with no TTY takes the stricter one. This flag exists so a scripted deploy stays scripted without
# relying on that default, and so the answer is visible in the command that gave it.
#
# --skip-preflight: the ONLY way to not grade this tree, and it is a command-line flag on purpose.
# It is NOT implied by --yes. --yes already means "stop asking me about the operational key", and a
# flag whose name is about one question must not quietly answer a different one; an operator typing
# --yes to get past a key prompt has said nothing at all about whether the code should be graded.
# There is deliberately NO environment variable for this. This project already refuses
# DEPLOY_POLICY_OVERRIDE, DEPLOY_ALLOW_DIRTY_REPO and DEPLOY_ALLOW_UNINDEXED_ARTEFACT for the same
# reason, and the reason is not squeamishness about bypasses: an env var is exported ONCE, into a
# shell profile or a CI environment, and is then the default for every later run, invisibly, for
# everyone, including the runs nobody meant to exempt. A flag has to be retyped on each invocation
# and it lands in shell history where it can be found afterwards. The bypass must cost a keystroke
# every time or it stops being a bypass and becomes the behaviour.
#
# --break-glass-only: the MIRROR of --enable-operational, and the reason it exists is that this script used
# to make the custody choice for the operator. The console's first-run ceremony offers both postures with no
# default selection; this path generated the operational pair unconditionally, printed the outcome on the
# sheet, and never asked. A flag is the smallest honest fix: the two paths now reach the same two postures,
# and the terminal one still states which it landed in.
ENABLE_OPERATIONAL=0
BREAK_GLASS_ONLY=0
SKIP_PREFLIGHT=0
BREAK_GLASS_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --enable-operational|--yes) ENABLE_OPERATIONAL=1 ;;
    --break-glass-only) BREAK_GLASS_ONLY=1 ;;
    --skip-preflight) SKIP_PREFLIGHT=1 ;;
    --break-glass-only) BREAK_GLASS_ONLY=1 ;;
  esac
done

# The two custody flags contradict each other, so the script refuses rather than letting an order-of-
# evaluation accident pick a posture. Silently preferring either one would install key material the operator
# did not ask for, which is the defect --break-glass-only exists to close.
if [ "$ENABLE_OPERATIONAL" = "1" ] && [ "$BREAK_GLASS_ONLY" = "1" ]; then
  echo "Refusing: --break-glass-only and --enable-operational (or --yes) ask for opposite key postures."
  echo "Pass exactly one: --break-glass-only for no operational key, --enable-operational to install one."
  exit 2
fi

# ============================================================================================
# BLOCKING PREFLIGHT. THE DEPLOY GRADES THE TREE BEFORE IT SHIPS.
# ============================================================================================
#
# WHY IT GRADES. The preflight runs typecheck, validate and lint under `set -e` before the script
# stamps the artefact, reconciles the bindings or calls `npx wrangler deploy`. A deploy that grades
# nothing cannot tell a repo that works from a repo that is broken, and it ships either one with the
# same confidence.
#
# WHY IT IS HERE, ABOVE THE RECONCILE AND THE BUILD, AND NOT LOWER DOWN. The two steps below this
# both MUTATE the tree: scripts/sync-bindings.mjs writes wrangler.deploy.toml, and
# scripts/build-deploy-bundle.mjs resets src/format/build-stamp.ts to its committed placeholder and
# writes .wrangler/deploy-bundle/. A preflight placed after either of them is no longer grading the tree the
# operator committed and asked to ship; it is grading a tree this script has already edited, and
# `npm run typecheck` would be reading the build's output rather than the committed source. The
# only position from which the preflight grades the thing under test is the top.
#
# It is also deliberately ABOVE the EXIT trap installed further down. That trap exists to tell an
# operator that a LIVE worker was left half-configured. Nothing is live yet up here, so a refusal
# at this point must not print that sentence: there is no deployed worker, no armed cron and no
# missing key to warn about. A preflight refusal is the cheap, boring, totally safe failure, and it
# should read like one.
#
# THIS IS THE CUSTOMER PREFLIGHT, NOT THE DEVELOPER CHAIN. The job differs. `npm run validate` exists
# so a developer never grades against a stale sibling: it compares this repo with the console, docs,
# other sibling and reader checkouts beside it, and it refuses when any of them is behind its own
# origin/main. A customer deploys a release tag, and a release tag is behind main as soon as anything
# lands after it, so the developer chain refused every customer deploy that followed /deploy with
# CANNOT CHECK. What a customer deploy must prove is that THIS tree is intact and deployable on THIS
# machine, and the full developer grade of the same commit already ran in CI. The developer chain is
# unchanged and stays exactly as strict; this preflight runs a different, named subset of it.
#
# WHAT RUNS, cheapest first, each one stopping the deploy on a failure or a could-not-check:
#   1. dependencies (`npm run lint:deps-installed`): node_modules matches package-lock.json. A tree
#      installed with anything other than `npm ci` can carry other versions of the crypto and format
#      libraries, and every later step would then grade code this lockfile does not describe.
#   2. typecheck (`tsc --noEmit` plus tsconfig.test.json). The validators run on node with types
#      stripped, so a type error is a thing validate cannot see.
#   3. build (`wrangler deploy --dry-run` into a temporary directory): the bundle this deploy uploads
#      builds from this tree. Nothing is uploaded and nothing is written into the tree.
#   4. validate:customer (`run-gate-chain.mjs validate:customer:chain`): the members of validate:chain
#      that guard the customer's data and keys. That is the archive bytes (crypto, format, seal, read,
#      restore, destination write and delete, WORM, anti-rollback), the keys (generation, install,
#      rotation, the configuration wrap key) and the code this script runs on this machine
#      (deploy.sh itself, generate-keys.ts, sync-bindings.mjs, build-deploy-bundle.mjs).
#
# WHAT IS LEFT OUT, AND WHY, is recorded member by member in scripts/customer-preflight.json, each with
# a one-line reason, and test/validate-customer-preflight.ts (a member of validate:chain) fails when a
# member of validate:chain is not classified there, so a new gate cannot slip out of both lists. The
# reasons are: it reads a sibling checkout or its freshness (cross-repo); it grades how this repo is
# developed (dev-process) or a document against the code (docs-parity); it grades a Worker feature
# that does not touch archive bytes or keys (identity, integrations, support, outbound-safety,
# worker-behaviour); or it depends on elapsed time under load (timing), because a customer machine
# can be busy and a timing failure would stop a deploy of correct code.
#
# HOW LONG IT TAKES, MEASURED on a fresh clone of the public export of this change, checked out at a
# release tag: dependencies 2 s, typecheck 33 s, build 23 s, validate:customer 680 s, 738 s in all, on a
# machine at load average 95 to 110. On the same machine and load the developer chain it replaces ran for
# 2,899 s and then refused; earlier measurements of that chain were 1,043 s and 1,409 s. At load average
# 15 to 30 the same preflight took 299 s (dependencies 1 s, typecheck 8 s, build 8 s, validate:customer 282 s).
#
# WHY LINT IS NOT A MEMBER beyond lint:deps-installed: the rest of the lint chain grades file lengths,
# prose and the development process, not the engine this deploy uploads. It runs in CI.
#
# BOTH A FAILURE AND A COULD-NOT-CHECK STOP THE DEPLOY, and they are told apart. run-gate-chain.mjs
# distinguishes exit 1, meaning every member graded its subject and here are the violations, from
# exit 2, meaning at least one member could not establish its subject so the run licenses no reading
# at all. `set -e` alone would stop on both while saying nothing about which, and exit 2 is the one
# an operator is most likely to misread as noise: it is what a stale sibling checkout produces, and
# it is not a pass. So the code is captured and named rather than merely obeyed.
# preflight_build builds the bundle `wrangler deploy` would upload, into a temporary directory that is
# removed afterwards, so the build is graded without writing into the tree or contacting the account.
preflight_build() {
  preflight_build_dir="$(mktemp -d "${TMPDIR:-/tmp}/downpipes-preflight-build.XXXXXX")" || return 2
  npx wrangler deploy --dry-run --outdir "$preflight_build_dir"
  preflight_build_exit=$?
  rm -rf "${preflight_build_dir:?}"
  return "$preflight_build_exit"
}

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
    echo "establish its own subject, so this run is not a grade and no member's silence means clean."
    echo "EXIT 2 IS NOT A PASS, which is why it stops this deploy exactly as a failure does. The"
    echo "usual causes are local rather than in the code: dependencies that do not match"
    echo "package-lock.json (run \`npm ci\`), or a member that could not reach something on this"
    echo "machine. The member is named above."
  else
    echo "PREFLIGHT ENDED at $preflight_label with exit $preflight_exit, which is outside the 0/1/2"
    echo "convention, so whether it graded anything at all is unknown. An unknown is not a pass."
  fi

  echo ""
  echo "NOTHING WAS DEPLOYED AND NOTHING WAS CHANGED. This ran before the binding reconcile and before"
  echo "the build, so src/format/build-stamp.ts and wrangler.deploy.toml are untouched,"
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
  echo "This deploy has NOT been checked. Its dependencies, types, build and the gates"
  echo "that guard your data and keys have not graded the code about to be uploaded."
  echo "=============================================================================="
  echo ""
else
  echo ""
  echo "Preflight: dependencies, typecheck, build and the checks that guard your data and keys."
  echo "It took 299 to 738 seconds (5 to 12 minutes) when measured, at load averages from 15 to 110."
  preflight_run "dependencies" npm run lint:deps-installed
  preflight_run "typecheck" npm run typecheck
  preflight_run "build" preflight_build
  preflight_run "validate:customer" npm run validate:customer
fi

# Preserve console-attached source bindings across this deploy. `wrangler deploy` REPLACES the
# worker's bindings with wrangler.toml's, which would silently drop any source attached from the
# console (those live on the worker, not in git). The reconcile reads the live bindings and writes
# wrangler.deploy.toml = wrangler.toml + the live sources; with set -e a refusal here stops the
# deploy rather than ship a binding-dropping config. See src/admin/bindings-sync.ts for the why.
node scripts/sync-bindings.mjs

# Build the bundle ONCE, hash it, and upload exactly that file (the `wrangler deploy` below passes
# --no-bundle, so wrangler uploads the file as it is). The hash rides to the engine as the plain-text
# binding DEPLOYED_ARTEFACT_SHA384, and GET /admin/status reports it as the SHA-384 of the served main
# module. It is recorded outside the bytes because a bundle cannot carry its own hash: writing the digest
# into src/format/build-stamp.ts and bundling again changes the bytes the digest was taken over. The bundle
# stays in .wrangler/deploy-bundle/ after the deploy, so
# `shasum -a 384 .wrangler/deploy-bundle/index.js` can be compared with the value status reports.
# test/validate-deploy-artefact-hash.ts drives these lines and checks the two agree.
DEPLOYED_ARTEFACT_SHA384="$(node scripts/build-deploy-bundle.mjs --config wrangler.deploy.toml --outdir .wrangler/deploy-bundle)"

# THE DEPLOY IS NO LONGER THE LAST THING THAT CAN KILL THIS SCRIPT IN SILENCE.
#
# WHAT HAPPENED, MEASURED RATHER THAN IMAGINED (on a genuinely fresh routeless worker following the
# published /deploy/ steps). `npx wrangler deploy` uploaded the worker,
# armed its cron and printed "Deployed ... triggers". Then wrangler 4.116.0 asked, on the way OUT of that
# SUCCESSFUL deploy, "Before you go, Wrangler detected AI coding agents ... install Cloudflare skills?",
# and the command ended non-zero. Under `set -e` this line was therefore the end of the script, BETWEEN a
# successful deploy and key generation. The state that left: a live engine with its schedule armed, no
# recovery-kit/, `wrangler secret list` empty. No signer key, no break-glass key, no admin token, and
# nothing anywhere telling the operator that re-running is safe.
#
# THE TRIGGER IS PARTLY OURS. wrangler raises that prompt when it detects an AI coding agent in the
# environment, and /deploy/'s own "hand the repetitive part to your AI assistant" section puts the customer
# in exactly that environment with a copy-paste prompt.
#
# THIS SCRIPT SURVIVES THE EXIT RATHER THAN SUPPRESSING THE PROMPT. Setting `CI=1` makes wrangler skip
# the prompt (it checks ci-info), but that suppresses THIS prompt in THIS version and nothing else, while the
# class of failure is wider: any non-zero from wrangler after a landed upload (a new prompt, a transient API error, a closed
# TTY) leaves the same deployed-but-keyless engine. It also tells wrangler an untruth about the environment,
# which suppresses prompts a real operator may want to see, and a human in a real terminal answers this one
# with a single keypress and needs no flag at all. Surviving the exit covers the whole class; suppressing
# one prompt covers one prompt.
#
# THE EXIT CODE IS NOT BELIEVED, THE ACCOUNT IS ASKED. A non-zero here has two opposite meanings, "the
# deploy failed" and "the deploy landed and wrangler died on the way out", and they want opposite actions.
# So the deployed version is read BEFORE and AFTER: if it moved, the upload landed whatever wrangler's exit
# code says, and key generation must continue, because stopping is what leaves the keyless engine. If it did
# not move, the deploy genuinely failed and the script stops, saying so, and saying that re-running is safe.
DEPLOY_LANDED=0
KEYS_SETTLED=0

# deployed_version prints the live worker's currently deployed version id, or nothing at all when the
# worker does not exist, has no deployment, or cannot be read. Never fails: an unreadable answer must not
# become a refusal, because this is only ever used as a BEFORE/AFTER comparison and two unreadable answers
# compare equal, which is the conservative outcome (treat the deploy as not proven to have landed).
#
# IT MATCHES THE UUID SHAPE RATHER THAN A LABEL, AND THAT IS A REPAIR OF THIS FUNCTION RATHER THAN ITS
# FIRST DRAFT. The first version grepped for "version id", which is what `wrangler versions list` prints
# and NOT what `wrangler deployments status` prints: 4.116.0 answers "Version(s):  (100%) <uuid>" there.
# So it returned empty before AND after, the two compared equal, and a landed deploy was reported as one
# that never happened. Caught by driving a real deploy against a throwaway worker rather than by reading
# the code, which is the only way that class of mistake shows up. A uuid has one shape across every label
# wrangler has used for it.
deployed_version() {
  npx wrangler deployments status -c wrangler.deploy.toml 2>/dev/null \
    | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    | head -1 || true
}

VERSION_BEFORE="$(deployed_version)"

set +e
npx wrangler deploy .wrangler/deploy-bundle/index.js --no-bundle -c wrangler.deploy.toml --var "DEPLOYED_ARTEFACT_SHA384:$DEPLOYED_ARTEFACT_SHA384"
WRANGLER_EXIT=$?
set -e

# AN EXIT 0 IS NOT BELIEVED EITHER. wrangler asks "Would you like to continue?" before it overwrites a
# worker that was last changed outside this checkout: most often "You are about to upload a Worker that
# was last updated via the script API", which every console source attach, key install or update apply
# produces, and also when the dashboard configuration or a remote secret differs. Answered no, wrangler
# uploads nothing and exits 0, and this script must not report a deploy that never happened and go on to
# key generation. So the deployed version is compared in both directions: the deploy landed when it
# moved, whatever the exit code said, and did not land when it stayed put, whatever the exit code said.
VERSION_AFTER="$(deployed_version)"
if [ -n "$VERSION_AFTER" ] && [ "$VERSION_AFTER" != "$VERSION_BEFORE" ]; then
  DEPLOY_LANDED=1
  if [ "$WRANGLER_EXIT" -ne 0 ]; then
    echo ""
    echo "NOTE: wrangler exited $WRANGLER_EXIT, but the upload LANDED: this worker's deployed version"
    echo "changed during the command. wrangler asks an unrelated question on the way out of a successful"
    echo "deploy (most often whether to install Cloudflare skills for a detected AI coding agent), and a"
    echo "non-answer ends the command non-zero. Continuing with key generation, which is the step that must"
    echo "not be skipped: an engine deployed without keys can seal nothing and has no way in."
    echo ""
  fi
elif [ "$WRANGLER_EXIT" -eq 0 ]; then
  echo ""
  if [ -z "$VERSION_AFTER" ]; then
    echo "The deploy could NOT be confirmed: wrangler exited 0, but this script could not read the worker's"
    echo "deployed version afterwards (\`npx wrangler deployments status -c wrangler.deploy.toml\`), so it"
    echo "cannot tell an upload from none. It stops here rather than generate keys for code it cannot see."
  else
    echo "NOTHING WAS DEPLOYED: wrangler exited 0, but this worker's deployed version did not change, so"
    echo "wrangler uploaded nothing. The usual cause is a \"Would you like to continue?\" answered no. wrangler"
    echo "asks it when the worker was last updated via the script API, which a console source attach, key"
    echo "install or update apply does, or when its dashboard configuration or secrets differ."
    echo ""
    echo "When the question followed \"last updated via the script API\", ANSWER YES (y). Before wrangler ran,"
    echo "this script read the live worker's bindings and wrote wrangler.deploy.toml with every source the"
    echo "console attached, so continuing keeps them. When it named a dashboard configuration or a secret"
    echo "that differs, read the difference wrangler printed first: continuing replaces the remote value"
    echo "with this checkout's."
  fi
  echo "No keys were generated and no secrets were set by this run, so nothing is half-done."
  echo ""
  echo "RE-RUNNING IS SAFE AND IS THE INTENDED NEXT STEP. \`npm run deploy\` resumes rather than restarts:"
  echo "it reads the live worker's bindings before deploying, and it generates keys only when this engine"
  echo "has none, so an engine that already has its keys keeps exactly the ones it has."
  echo ""
  exit 1
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

# AND THE SAME SENTENCE ON EVERY OTHER WAY OUT, because the deploy is not the only step between a live
# worker and a usable one. `wrangler secret put` runs six times below on a default fresh deploy, which is
# break-glass-only (seven in two-recipient, where the operational pair replaces the retired marker), the first-Owner bootstrap reads from
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

# CONFIG_WRAP_KEY_INSTALLED records that a fresh ceremony below already PUT the wrap key. The top-up after
# the key branch cannot infer it from $SECRETS, which was read before any put ran, and a second put would
# replace the key the ceremony just installed. It is a variable rather than a re-read of the secret list
# because a re-read costs an API call to learn something this script already knows.
CONFIG_WRAP_KEY_INSTALLED=0

if printf "%s" "$SECRETS" | grep -q '"SIGNER_PRIVATE"'; then
  echo "Keys are set (SIGNER_PRIVATE present); skipping key generation."
  if printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_PRIVATE"'; then
    if printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_RETIRED"'; then
      # The marker AND a private: break-glass-only was chosen, but a delete did not happen. The engine honours
      # the marker (it seals to break-glass alone and opens no run with this key), but the key is still in the
      # account and still decrypts runs sealed to it. This script does not delete key material (see below), so
      # it names the screen that does.
      echo "Break-glass-only was chosen on this engine (OPERATIONAL_RETIRED is set), but OPERATIONAL_PRIVATE"
      echo "is still set. The engine does not use it, but it can still decrypt runs sealed to it. Remove it:"
      echo "Keys screen, Posture tab, switch to break-glass only."
    else
      echo "Automated restore proof is on (OPERATIONAL_PRIVATE present)."
    fi
    if [ "$BREAK_GLASS_ONLY" = "1" ]; then
      # --break-glass-only never DELETES key material. Removing a live operational key can strand an
      # archive that key alone opens, which is why the console's switch is confirm-gated and guarded
      # (POST /admin/keys/break-glass-only refuses with 409 when it would strand one). A deploy flag has
      # no way to make that judgement or to show the impact, so it declines and names the screen that can.
      echo "--break-glass-only does NOT remove an operational key that already exists: deleting it can"
      echo "strand archives it alone opens. Use the Keys screen (Posture tab), which shows the impact"
      echo "and refuses when a run would be left unreadable."
    fi
  elif [ "$BREAK_GLASS_ONLY" = "1" ]; then
    # The engine has a signer and no operational key, and the operator asked for break-glass-only. Install
    # the durable marker rather than only skipping this run's generation: without it, the very next plain
    # `npm run deploy` would auto-generate an operational key and quietly undo the choice, which is the
    # same silent reversal B7 closed for the console's switch.
    echo "Break-glass-only requested: NOT generating an operational key."
    printf "true" | npx wrangler secret put OPERATIONAL_RETIRED
    echo "Installed the OPERATIONAL_RETIRED marker, so later deploys keep this posture."
    echo "This engine cannot read its own archives: scheduled restore tests and drills, and scheduled"
    echo "retention pruning, stay off until the Keys screen installs an operational key. Every read needs"
    echo "identity.key. An in-console restore or prune still works when you supply identity.key in the browser."
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
    OPERATIONAL_MARKER_SET=0
    if printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_RETIRED"'; then
      OPERATIONAL_MARKER_SET=1
      echo "OPERATIONAL_RETIRED is set (break-glass-only was chosen previously), but --enable-operational"
      echo "was passed: generating a fresh operational key anyway. The marker is removed first, because the"
      echo "engine seals to break-glass alone while it is set, whatever operational key is present."
    fi
    # KEYS PRESENT, NO OPERATIONAL KEY, NO MARKER: ASK, DO NOT ASSUME. This arm used to install an
    # operational key with no prompt, on the theory that the state meant "never provisioned". It does not only
    # mean that. The console's first-run ceremony installs keys with no operational pair when the operator
    # chooses strict break-glass-only, and it used to write no OPERATIONAL_RETIRED marker, so the next
    # plain `npm run deploy` silently installed a decryption-capable key on an engine whose owner had chosen the
    # opposite. The fresh-install arm below already asks and defaults to break-glass-only for the reason it
    # states (strict can be relaxed later with no re-key; two-recipient cannot be undone for sealed runs), and
    # this arm now does the same. The ceremony also writes the marker now (attach.ts installEngineSecrets).
    INSTALL_OPERATIONAL_NOW=0
    if [ "$ENABLE_OPERATIONAL" = "1" ]; then
      INSTALL_OPERATIONAL_NOW=1
    elif [ -t 0 ]; then
      echo "This engine has keys but no operational key, so it is break-glass-only now."
      echo "  1) Keep break-glass-only. The engine holds no key that can read your archives."
      echo "  2) Add an operational key, so the engine verifies its own backups on a schedule."
      echo "     A compromise of this Cloudflare account can then read your archives."
      printf "Enter 1 or 2 [1]: "
      read -r KEEP_CHOICE
      if [ "$KEEP_CHOICE" = "2" ]; then INSTALL_OPERATIONAL_NOW=1; fi
    fi
    if [ "$INSTALL_OPERATIONAL_NOW" = "1" ]; then
      echo "Enabling automated restore proof (the operational key was not set)..."
      node scripts/generate-keys.ts ./recovery-kit --operational-only
      # The marker goes before the pair, as the console's add does (attach.ts clearOperationalRetiredMarker):
      # a pair set beside a marker that stayed would be installed and never used.
      if [ "$OPERATIONAL_MARKER_SET" = "1" ]; then
        printf 'y\n' | npx wrangler secret delete OPERATIONAL_RETIRED
      fi
      npx wrangler secret put OPERATIONAL_PUBLIC < ./recovery-kit/.staging/operational-public.b64
      npx wrangler secret put OPERATIONAL_PRIVATE < ./recovery-kit/.staging/operational-private.b64
      rm -rf ./recovery-kit/.staging
      rmdir ./recovery-kit 2>/dev/null || true
      echo "Done: scheduled restore tests, drills and in-console restores now run."
      echo "Runs sealed before this moment stay break-glass-only; new runs verify."
    else
      echo "Keeping break-glass-only: NOT generating an operational key."
      printf "true" | npx wrangler secret put OPERATIONAL_RETIRED
      echo "Installed the OPERATIONAL_RETIRED marker, so later deploys keep this posture."
      echo "To add an operational key later: the Keys screen, or re-run this deploy with --enable-operational."
    fi
  fi
else
  # THE POSTURE CHOICE, PRESENTED RATHER THAN ASSUMED (the two ceremonies now agree).
  #
  # MERGE NOTE: this branch used to be split in two -- a separate `elif BREAK_GLASS_ONLY`
  # arm ran its own copy of the break-glass-only ceremony (same generate-keys.ts call, same secret puts,
  # older wording) BEFORE this posture-choice block ever ran, so the two arms silently duplicated one
  # another and the arm below could never see BREAK_GLASS_ONLY=1 at all: the elif upstream always claimed
  # it first, regardless of ENABLE_OPERATIONAL. That made "explicit --enable-operational wins when both
  # flags are somehow set" unreachable dead code below, and the two arms' wording had already drifted (the
  # deleted arm said "Generating this engine's keys on this machine, BREAK-GLASS-ONLY..."; this one says
  # "Posture installed: BREAK-GLASS-ONLY (...)" and names WHY). The deleted arm did nothing this one does
  # not already do -- same generator call, same seven secret puts, same marker -- so removing it costs
  # nothing and gives BREAK_GLASS_ONLY exactly one place to be decided.
  #
  # WHAT THIS BRANCH USED TO DO, AND WHY IT WAS THE WEAKER HALF OF AN ASYMMETRY. It PUT
  # OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE unconditionally, with no prompt and no flag, and told the
  # operator afterwards. The console ceremony for the same install puts the same trade-off in front of the
  # operator and, on an unrecorded choice, falls to the STRICTER posture
  # (console/src/screens/onboarding/carousel-cards-connect-keys.ts: "falling strict is the safe direction").
  # So the same product installed a decryption-capable key in the engine, or did not, purely on which
  # ceremony the operator happened to use, and the terminal was the half that never asked. The engine's own
  # architecture disclosure named this asymmetry and called the terminal outcome the weaker posture.
  #
  # WHY THE STRICT DEFAULT IS THE SAFE ONE, and it is not symmetry for its own sake: break-glass-only can be
  # relaxed later with NO re-key (POST /admin/keys/add-operational installs a fresh pair and clears the
  # marker), while two-recipient cannot be undone for archives ALREADY SEALED under the operational key --
  # the recipient set is baked in at seal time and is never rewrapped. One direction is a decision that can
  # be revisited; the other is permanent for every run taken before it is revisited.
  #
  # HOW THE ANSWER ARRIVES, and the last line is the one that decides an unattended install:
  #   --enable-operational / --yes   two-recipient, the pre-existing flag, unchanged in meaning
  #   --break-glass-only             break-glass-only, the explicit opposite, so a script stays a script
  #   neither, on a TTY              ask; the default on a bare Enter is break-glass-only
  #   neither, with no TTY           break-glass-only, and say what was skipped and how to add it later
  INSTALL_OPERATIONAL=0
  if [ "$ENABLE_OPERATIONAL" = "1" ]; then
    INSTALL_OPERATIONAL=1
    POSTURE_REASON="--enable-operational (or --yes) was passed"
  elif [ "$BREAK_GLASS_ONLY" = "1" ]; then
    POSTURE_REASON="--break-glass-only was passed"
  elif [ -t 0 ]; then
    echo ""
    echo "Custody posture for this engine. Choose before the keys are generated:"
    echo "  1) Break-glass-only. The engine holds NO key that can read your archives. Only the"
    echo "     offline identity.key you are about to be given opens them. The engine cannot"
    echo "     test-restore its own backups, so restore proof is attended, by you."
    echo "  2) Two-recipient. The engine also holds an operational key, so it verifies its own"
    echo "     backups on a schedule and in-console restores work unattended. A compromise of"
    echo "     this Cloudflare account can then read your archives."
    echo ""
    echo "1 can be relaxed later with no re-key (the Keys screen adds an operational key)."
    echo "2 cannot be undone for archives sealed while the operational key was present."
    printf "Enter 1 or 2 [1]: "
    read -r POSTURE_CHOICE
    if [ "$POSTURE_CHOICE" = "2" ]; then
      INSTALL_OPERATIONAL=1
      POSTURE_REASON="you chose two-recipient at the prompt"
    else
      POSTURE_REASON="you chose break-glass-only at the prompt"
    fi
  else
    POSTURE_REASON="no posture flag was given and this is not an interactive terminal"
  fi

  echo "Generating this engine's keys on this machine (nothing is sent to the vendor)..."
  if [ "$INSTALL_OPERATIONAL" = "1" ]; then
    node scripts/generate-keys.ts ./recovery-kit
  else
    # --break-glass-only is passed to the generator, not just to the installer. The operational pair is
    # then never created at all, and the printed recovery sheet states the posture the engine actually
    # holds; generating a key, declining to install it and handing over a sheet that says "restore proof:
    # ON" would leave the operator with a written record of a posture they do not have.
    # --posture-reason carries HOW break-glass-only was chosen (the flag, the prompt, or the no-terminal
    # default) onto the sheet. The generator gets --break-glass-only on all three paths, so without it the
    # sheet could only name the flag, which is false for the prompt and the default.
    node scripts/generate-keys.ts ./recovery-kit --break-glass-only "--posture-reason=$POSTURE_REASON"
  fi
  npx wrangler secret put SIGNER_PRIVATE < ./recovery-kit/.staging/signer-private.b64
  npx wrangler secret put BREAK_GLASS_PUBLIC < ./recovery-kit/.staging/break-glass-public.b64
  if [ "$INSTALL_OPERATIONAL" = "1" ]; then
    # A marker left from an earlier install would outrank the new pair (the engine seals to break-glass alone
    # while it is set), so it goes first.
    if printf "%s" "$SECRETS" | grep -q '"OPERATIONAL_RETIRED"'; then
      printf 'y\n' | npx wrangler secret delete OPERATIONAL_RETIRED
    fi
    npx wrangler secret put OPERATIONAL_PUBLIC < ./recovery-kit/.staging/operational-public.b64
    npx wrangler secret put OPERATIONAL_PRIVATE < ./recovery-kit/.staging/operational-private.b64
  else
    # The durable marker, written on the way IN rather than only on a later switch. It is the same secret
    # POST /admin/keys/break-glass-only writes (attach.ts removeOperationalSecrets) and the same one the
    # already-keyed branch above refuses to override without --enable-operational, so this deploy's choice
    # is protected on every later deploy by machinery that already exists. Its value is the fixed flag
    # "true"; its presence is the signal, to this script and to the running engine (keys-env.ts).
    printf "true" | npx wrangler secret put OPERATIONAL_RETIRED
  fi
  # The config recipient goes in for BOTH postures. It opens this engine's own configuration export and
  # nothing else, so removing the operational key later does not cost the engine its own config recovery.
  npx wrangler secret put CONFIG_RECIPIENT_PUBLIC < ./recovery-kit/.staging/config-recipient-public.b64
  npx wrangler secret put CONFIG_RECIPIENT_PRIVATE < ./recovery-kit/.staging/config-recipient-private.b64
  # The CONFIG WRAP KEY, generated by the same ceremony. It was optional and NOTHING generated it, so a
  # terminal deploy left every console-stored credential on the Durable Object plaintext floor -- the
  # destination credential, the SIEM and notify integration secrets, and the account-wide read-only
  # Cloudflare discovery token -- until an operator read the recovery sheet and minted one by hand.
  # Installing it here is safe in the way installing a signing key is not: losing it costs a re-entered
  # credential (src/admin/config-secret.ts's own recovery text) and never an archive byte.
  npx wrangler secret put CONFIG_WRAP_KEY < ./recovery-kit/.staging/config-wrap-key.b64
  CONFIG_WRAP_KEY_INSTALLED=1
  rm -rf ./recovery-kit/.staging
  echo ""
  echo "IMPORTANT: ./recovery-kit/ now holds identity.key (your break-glass private"
  echo "key — the only way to read backups if the engine is lost) and the printable"
  echo "recovery sheet. Move the folder to offline storage and remove it from this"
  echo "machine. There is no server-side copy."
  if [ "$INSTALL_OPERATIONAL" = "1" ]; then
    echo "Posture installed: TWO-RECIPIENT ($POSTURE_REASON)."
    echo "Automated restore proof is ON: the engine verifies its own backups on a"
    echo "schedule (the operational key). Strict break-glass-only custody is the"
    echo "opt-out on the console's Keys screen."
  else
    echo "Posture installed: BREAK-GLASS-ONLY ($POSTURE_REASON)."
    echo "No operational key was installed, so the engine holds nothing that can read"
    echo "your archives and it cannot test-restore them on its own. Restore proof is"
    echo "attended: use the console's Restore screen with your identity.key."
    echo "To turn automated restore proof on later, use the console's Keys screen"
    echo "(Posture tab), or re-run this deploy with --enable-operational."
  fi
fi

# This engine's keys are settled: either they were already present, or they have just been generated and
# installed. From here a stop costs the first-Owner bootstrap and nothing custodial, so the trap above
# switches to the narrower sentence below rather than warning about keys that exist.
KEYS_SETTLED=1

# The CONFIG WRAP KEY top-up runs AFTER the keys-settled marker deliberately: the wrap key is a
# CONFIGURATION secret, not archive key material, so a failure here must not print the trap sentence that
# warns this engine may have no signer or break-glass key.
#
# The top-up itself is for an engine deployed BEFORE the ceremony minted one. Without this the fix
# above would close the plaintext floor for new estates only, and every engine already in the field would
# stay open until an operator read the sheet. Installing the key on a running engine migrates nothing and
# breaks nothing: the stored-shape check (src/admin/config-secret.ts isWrappedSecret) reads a plaintext
# credential and an envelope alike, so existing records keep working and each is wrapped the next time its
# destination or integration is saved. The dest-cred-encryption posture check keeps failing while any
# plaintext record remains (posture-checks.ts buildDestCredEncryption counts them), so the tail stays
# visible rather than reading as closed the moment the key lands.
if ! printf "%s" "$SECRETS" | grep -q '"CONFIG_WRAP_KEY"'; then
  if [ "$CONFIG_WRAP_KEY_INSTALLED" != "1" ]; then
    echo "Generating this engine's configuration wrap key (console-stored credentials are encrypted at rest)..."
    node scripts/generate-keys.ts ./recovery-kit --config-wrap-key-only
    npx wrangler secret put CONFIG_WRAP_KEY < ./recovery-kit/.staging/config-wrap-key.b64
    rm -rf ./recovery-kit/.staging
    rmdir ./recovery-kit 2>/dev/null || true
    echo "Credentials saved BEFORE now stay on the platform-encryption floor until each destination or"
    echo "integration is re-saved. The console's Security centre counts the ones still on the old floor"
    echo "(the 'Destination credentials encrypted at rest' check), and keeps failing until none remain."
  fi
fi

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
  #   2) admin token - no email; a break-glass bearer, valid until retired, pasted into the console
  #      at sign-in, claims the first Owner while the role table is still empty.
  echo ""
  echo "First-Owner set-up. Choose how you will claim the first Owner account:"
  echo "  1) Email link  (needs Cloudflare Email Sending)"
  echo "  2) Admin token (no email; break-glass bearer, valid until retired)"
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
    # Default / fallback: the no-email break-glass path. Generate a token, set it
    # as ADMIN_TOKEN, and print it ONCE (it is never echoed by wrangler and there is no copy to
    # recover later). While the role table is empty this bearer claims the first Owner; after that
    # it is a standing break-glass credential and should be retired.
    ADMIN_TOKEN_VALUE="$(openssl rand -base64 32)"
    printf "%s" "$ADMIN_TOKEN_VALUE" | npx wrangler secret put ADMIN_TOKEN
    echo ""
    echo "First-Owner admin token (shown ONCE, not stored anywhere you can read back):"
    echo ""
    echo "    $ADMIN_TOKEN_VALUE"
    echo ""
    echo "To become the first Owner: open your console, choose the break-glass / admin-token"
    echo "sign-in on the sign-in page, and paste this token. While no Owner exists it claims the"
    echo "first Owner; you then enrol a passkey."
    echo ""
    echo "POSTURE: this token does not expire. It stays valid until you retire it. Once an Owner"
    echo "with a way back in exists (recovery codes, or a second Owner), retire it in the console"
    echo "(Security Centre > Retire break-glass token) or delete the secret"
    echo "(npx wrangler secret delete ADMIN_TOKEN). Leaving it live lets anyone with the string take admin."
  fi
fi
