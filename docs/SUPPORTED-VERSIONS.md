# Supported versions

This page states which engine releases get fixes, how long each release stays supported,
and how the engine tells an operator that the running release is near its end of support.

## The rule

- A fix ships only in the next release. The vendor does not backport a fix to an earlier
  release.
- A release is supported until 90 days after its successor ships. The successor is the
  next release. After that date the release is end of life.
- `supportedUntil` of a release is the release time of its successor plus 90 days, in UTC.
- The latest release has no successor. It has no `supportedUntil`, and it is supported.
- The console shows a notice from 30 days before `supportedUntil`, and after it.
- No date is typed by hand. Every date comes from the signed update channel.

### Example

`0.3.8` ships at `2026-10-11T02:44:52.944Z`, the time the signed channel records for it.

- `0.3.7` is supported until `2027-01-09T02:44:52.944Z`, which is 90 days later.
- From `2026-12-10T02:44:52.944Z`, 30 days before that date, the console shows a notice for `0.3.7`.
- After `2027-01-09T02:44:52.944Z`, `0.3.7` is end of life, and the console shows a stronger notice.
- `0.3.8` is supported until 90 days after the time the channel records for `0.3.9`.
- `0.3.9` is the latest release, so it has no `supportedUntil`.

The severity of a security fix, and the time to ship it, follow the remediation SLA in
[SECURITY.md](../SECURITY.md#risk-based-remediation-sla).

## How the engine tells you

The signed update channel carries `releases`, a map from each
release version to the time it shipped:

```jsonc
"releases": {
  "0.3.7": "2026-10-05T08:36:27.777Z",
  "0.3.8": "2026-10-11T02:44:52.944Z"
}
```

- The map is inside the channel signature. Nobody can change a date without the pinned
  release-signer key.
- The map only grows. The publisher (`tools/publish-channel.mjs --previous-channel <path>`)
  reads the previous signed channel, verifies it, carries every earlier date forward
  unchanged, and adds the new release. A release keeps the date it first had.
- A publish needs `--previous-channel`, or `--first-release` for the very first channel.
- The publisher has no input for a release date or a support date. It refuses `--released-at`,
  `--supported-until` and the matching meta-file fields. The release date is the time of the
  publish run.
- The engine finds its successor: the lowest release above the running version in semver
  order that the map dates. It reports `supportedUntil` and `supportStatus` for the running
  version on `GET /admin/updates` (`src/admin/update-support.ts`).
- `supportStatus` is `supported` (no successor, or more than 30 days left), `ending` (30 days
  or fewer left) or `end-of-life` (the date is past).
- A channel with no `releases` map gives neither field, and the console shows no notice.
- An engine that predates the map ignores it. A malformed map, key or date never stops the
  update check. The engine reports no `supportedUntil` and logs a warning.

## What end of life means for you

- The engine keeps running. Backups and restores do not stop on the end date.
- The vendor ships no more fixes for that release, including security fixes.
- Update to the latest release from the Updates section. The update path is the same as for
  any other release.
