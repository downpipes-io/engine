#!/bin/sh
# notifyalert-mutants.sh -- does the notify-alert drive actually KILL a planted defect, or only pass?
#
# STRICTLY SERIAL by construction: one mutant is planted, scored and byte-restored before the next is
# planted. Nothing else may import the mutated file while this runs.
#
# For every mutant:
#   * the anchor literal is ASSERTED to occur EXACTLY ONCE in src/ before planting, so the edit cannot
#     silently hit a second site
#   * the file's sha256 is asserted MOVED after planting (a plant that did not change the file would
#     otherwise be scored as a surviving mutant, which reads as a blind test)
#   * the restore is a BYTE COPY from a pristine copy taken before the plant, never `git checkout`, which
#     restores to the last commit and destroyed five uncommitted corrections in this workspace today
#   * the sha256 is re-asserted EQUAL after the restore
#   * each mutant's output goes to its OWN file, and its exit code is read OFF THE PROCESS
#
# M5 is the CONTROL and must SURVIVE: it changes a comment only. A run where the comment mutant dies is a
# test keyed on something other than behaviour.
set -u
BED="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:?usage: notifyalert-mutants.sh <output-dir>}"
mkdir -p "$OUT"
DRIVER="test/runtime/runtime.notifyalert-keepalive.test.mjs"
cd "$BED" || exit 9

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# plant <n> <file> <python-edit-expr> <cases> <expect kill|survive> <what>
plant() {
  N=$1; F=$2; EDIT=$3; CASES=$4; EXPECT=$5; WHAT=$6
  echo "=== M$N ($EXPECT) $WHAT"
  BEFORE=$(sha "$F")
  cp "$F" "$OUT/M$N.pristine"
  python3 - "$F" "$EDIT" <<'PY' || { echo "M$N: PLANT REFUSED"; return 1; }
import sys
f, edit = sys.argv[1], sys.argv[2]
old, new = edit.split("|@|")
s = open(f).read()
n = s.count(old)
if n != 1:
    print(f"anchor occurs {n} times, not exactly once: {old[:60]}")
    sys.exit(1)
open(f, "w").write(s.replace(old, new))
PY
  AFTER=$(sha "$F")
  if [ "$BEFORE" = "$AFTER" ]; then
    echo "M$N: THE FILE DID NOT MOVE -- this mutant is not planted, so its score means nothing"
    cp "$OUT/M$N.pristine" "$F"
    return 1
  fi
  echo "M$N: sha moved $BEFORE -> $AFTER"
  node "$DRIVER" --n 3 --only "$CASES" > "$OUT/M$N.log" 2>&1
  CODE=$?
  echo "M$N: driver exit $CODE (read off the process)"
  cp "$OUT/M$N.pristine" "$F"
  RESTORED=$(sha "$F")
  if [ "$RESTORED" != "$BEFORE" ]; then
    echo "M$N: RESTORE DID NOT MATCH ($RESTORED vs $BEFORE) -- STOPPING"
    exit 9
  fi
  echo "M$N: restored by byte copy, sha re-asserted EQUAL"
  if [ "$EXPECT" = "kill" ]; then
    [ "$CODE" -eq 1 ] && echo "M$N: KILLED" || echo "M$N: SURVIVED (exit $CODE) -- THE TEST IS BLIND TO THIS DEFECT"
  else
    [ "$CODE" -eq 0 ] && echo "M$N: SURVIVED as required" || echo "M$N: THE COMMENT CONTROL DIED (exit $CODE) -- the test is keyed on something other than behaviour"
  fi
  echo ""
}

plant 1 src/admin/router-posture.ts \
  'if (keepAlive) keepAlive(routed);
    else await routed;|@|void routed;' \
  posture-regression kill "the repair reverted: the caller drops the alert promise again"

plant 2 src/admin/router-rbac.ts \
  'Member removed (offboarded)${body.email|@|Role changed${body.email' \
  offboard-console kill "the offboard alert files under the ROLE-GRANT route name (event, class, counts and row count all unchanged)"

plant 3 src/admin/router-identity.ts \
  'An IdP connection removal was requested|@|An IdP connection add was requested' \
  idp-delete kill "the IdP REMOVAL alert files under the IdP ADD route name (the wrong-surface mutant an existence check passes)"

plant 4 src/admin/router-account-session.ts \
  '"auth-credential-change", "credential-change", `Every sign-in factor|@|"auth-credential-change", "offboard", `Every sign-in factor' \
  factors-revoke kill "the all-factors revoke is recorded under a different ALERT CLASS"

plant 4b src/admin/router-auth-flow.ts \
  'enrolled.enrolmentPath === "self-add"|@|enrolled.enrolmentPath === "self-added"' \
  passkey-self-add kill "the passkey SELF-ADD alert is gated on a path value the DO never produces, so it never fires (V6.3.7)"

plant 5 src/admin/router-posture.ts \
  '// THE PROMISE IS KEPT INSTEAD OF DROPPED|@|// THE PROMISE IS KEPT RATHER THAN DROPPED' \
  posture-regression survive "COMMENT ONLY -- the control that must survive"
