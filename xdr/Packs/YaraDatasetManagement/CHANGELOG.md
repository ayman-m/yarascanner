## [1.4.0] - 2026-09-01

#### YARA Scanner (Action Center script)
- **Proxy support.** `CONFIG_PROXY` takes one URL used for both schemes. Endpoints that
  cannot reach the tenant directly had no way to say so: `requests` honours `HTTPS_PROXY`
  only when the process environment carries it, and an Action Center script's does not.
  The comment carries worked examples and names the trap - the scheme is how you reach the
  PROXY, not the scheme of the traffic, so `http://` is right for almost every corporate
  proxy even though the tenant API is https.
- **`CONFIG_VERIFY_TLS = False`.** A TLS-intercepting proxy presents its own certificate,
  which cannot validate against the public roots; with verification on and that CA absent
  from the endpoint's trust store, every upload fails at the transport while the scan runs
  to completion locally and delivers nothing. Off by default so no CA has to be distributed.
  Traffic stays encrypted but the server is not authenticated - set it True where the
  network path is not trusted. Announced on stderr on every run that uses it.
- **Diagnostics on by default.** Performance and resource monitoring were env-var-only and
  defaulted off, so they were unreachable from the Action Center and the logs that explain a
  slow scan could only be enabled by editing the script.
- **The runtime profile is real.** `light_profile` was hardcoded and read nowhere while the
  summary reported `scanner_profile: 'light'` and the startup log claimed "reduced workers,
  reduced monitoring" on every run - none of which was true. `CONFIG_PROFILE` now selects
  `full` or `light`, light genuinely turns the monitors off, and the log states plainly that
  workers and CPU are governed separately and unaffected by the profile.

All of these are CONFIG constants edited once in the script. The Action Center inputs are
unchanged and remain `yarafile`, `scan_folder`, `alert_severity` - `core-script-run` rejects
any parameter set that does not exactly match the declared inputs.

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
