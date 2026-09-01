## [1.3.0] - 2026-09-01

Nine automations and one playbook, verified end to end against a live Cortex XDR tenant.

#### YARA Dataset Management
- **Consolidation reconciles correctly.** Stale rows are computed as `held - observed`, so a
  `scan_id`-filtered run no longer removes rows belonging to hosts it was never asked to
  touch. An unreadable source now disables stale removal for the whole pass and says so.
- **Eligibility is `(terminal AND quiet) OR aged`.** The scanner writes its terminal
  lifecycle row before draining its uploaders, so `completed` does not mean the rows landed.
  A finished scan is held for 900s after its newest row before it is grouped; consolidating
  inside that window would copy a partial set, permanently.
- **`remove_lookup_data` reconciliation works.** The filter shape sent to the API had been
  rejected for the life of the call, so stale rows accumulated while the run reported
  failure. Verified live: a superseded scan is now dropped from the consolidated output.
- **`YaraWipeAllDatasets` no longer takes over a lock it cannot read.** An unreadable lock
  marker is the ordinary create-lag window right after another run took it; treating it as
  stale allowed a wipe to delete every dataset out from under a live consolidation. A lock
  standdown is also recorded in the run log rather than passing silently.
- **Playbook conditions test emptiness correctly.** `isExists` is true for a declared-but-
  empty value, so every successful pass flagged itself as needing attention and the
  wait-for-in-progress branch could never be reached. Both playbooks now use `isNotEmpty`.
- **New:** `YaraScanVerify` (bounded post-dispatch check that a wave started),
  `YaraRulesFromFile` (validate an uploaded rules file, emit base64 and the ruleset hash),
  `YaraRulesDecode` (the inverse, for verification and forensics).
- `YaraRulesFromFile` finds an uploaded file the way Cortex content does — `File.EntryID`,
  then the newest War Room file entry, then incident attachments — and takes `entryID`.

## [1.2.0] - 2026-08-20

- Removed `YaraConsolidateCommon`, a shared library that nothing imported and no playbook
  reached. Each automation is standalone because the platform resolves no cross-script
  imports.

## [1.1.0] - 2026-08-10

- Per-scan dataset consolidation, in full-detail and summary modes.

## [1.0.0] - 2026-08-03

- Initial release.
