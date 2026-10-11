#!/usr/bin/env bash
# verify-tag-on-main.sh: refuses a release tag whose commit is not on main.
#
# Usage:
#   verify-tag-on-main.sh <tag>
#   verify-tag-on-main.sh --self-test
#
# The release workflow builds from whatever commit a correctly signed tag names. A signed tag on
# a pull request head, or on any commit that never reached main, would otherwise build a release.
# This check reads the tag's commit and requires it to be an ancestor of origin/main in the
# current checkout. The checkout must be a full one (fetch-depth 0): the workflow does not
# persist credentials, so this script never fetches. It fails closed: a missing tag, a missing
# origin/main, a shallow checkout and a commit off main all exit 1.
set -euo pipefail

refuse() {
  echo "::error::$*" >&2
  exit 1
}

verify() {
  local tag="$1" tag_sha
  [[ -n "$tag" ]] || refuse "no tag name was given; usage: verify-tag-on-main.sh <tag>"
  tag_sha="$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" \
    || refuse "tag $tag is not in this checkout, so the commit it names cannot be checked against main."
  git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null \
    || refuse "origin/main is missing from the checkout, so tag $tag cannot be checked against main."
  [[ "$(git rev-parse --is-shallow-repository)" == "false" ]] \
    || refuse "the checkout is shallow, so the ancestry of tag $tag cannot be proven; use fetch-depth 0."
  if ! git merge-base --is-ancestor "$tag_sha" refs/remotes/origin/main; then
    refuse "tag $tag names commit $tag_sha, which is not on main. A release is built only from a commit that has been merged to main."
  fi
  echo "tag $tag names commit $tag_sha, which is on main"
}

self_test() {
  local work failed=0 checked=0
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  local self
  self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  local g=(git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false)

  "${g[@]}" init -q --bare "$work/remote.git"
  "${g[@]}" init -q -b main "$work/src"
  (
    cd "$work/src"
    "${g[@]}" commit -q --allow-empty -m one
    "${g[@]}" commit -q --allow-empty -m two
    "${g[@]}" tag -a -m on-main-old v1.0.0 HEAD~1
    "${g[@]}" tag -a -m on-main-tip v1.0.1
    "${g[@]}" tag v1.0.2
    "${g[@]}" remote add origin "$work/remote.git"
    "${g[@]}" push -q origin main
    "${g[@]}" checkout -q -b pr-branch
    "${g[@]}" commit -q --allow-empty -m pr-only
    "${g[@]}" tag -a -m off-main v2.0.0
    "${g[@]}" tag v2.0.1
    "${g[@]}" push -q origin pr-branch --tags
  )

  # A tag push checkout: full history, every branch and tag, origin/main present.
  "${g[@]}" clone -q --no-local "$work/remote.git" "$work/full"
  "${g[@]}" clone -q --no-local --depth 1 --no-single-branch "file://$work/remote.git" "$work/shallow"
  (cd "$work/shallow" && "${g[@]}" fetch -q --depth 1 origin tag v1.0.1)
  "${g[@]}" init -q "$work/nomain"
  (cd "$work/nomain" && "${g[@]}" commit -q --allow-empty -m x && "${g[@]}" tag -a -m x v3.0.0)

  expect() { # <dir> <tag> <want status> <desc>
    local dir="$1" tag="$2" want="$3" desc="$4" status=0 out
    checked=$((checked + 1))
    out="$(cd "$dir" && bash "$self" "$tag" 2>&1)" || status=$?
    if [[ "$status" != "$want" ]]; then
      echo "verify-tag-on-main --self-test FAIL: $desc (wanted exit $want, got $status): $out" >&2
      failed=$((failed + 1))
    fi
  }

  expect "$work/full" v1.0.0 0 "annotated tag on an older main commit is accepted"
  expect "$work/full" v1.0.1 0 "annotated tag on the main tip is accepted"
  expect "$work/full" v1.0.2 0 "lightweight tag on the main tip is accepted"
  expect "$work/full" v2.0.0 1 "annotated tag on a commit that is not on main is refused"
  expect "$work/full" v2.0.1 1 "lightweight tag on a commit that is not on main is refused"
  expect "$work/full" v9.9.9 1 "a tag that does not exist is refused"
  expect "$work/nomain" v3.0.0 1 "a checkout with no origin/main is refused"
  expect "$work/shallow" v1.0.1 1 "a shallow checkout is refused"
  expect "$work/full" "" 1 "an empty tag name is refused"

  if [[ "$failed" != 0 ]]; then
    echo "verify-tag-on-main --self-test: $failed of $checked assertion(s) failed" >&2
    return 1
  fi
  echo "verify-tag-on-main --self-test: $checked of $checked assertion(s) passed"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit $?
fi
verify "${1:-}"
