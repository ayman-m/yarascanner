## [1.6.0] - 2026-09-07

#### Every automation: markdown reports, and results as objects rather than sentences

All nine automations now render their War Room output as markdown - a headline, a key/value
fact table, then one table per outcome - and the report is rendered FROM the result dict, so
the table an operator reads and the context a playbook branches on cannot state different
numbers.

The result lists that held preformatted strings now hold OBJECTS with a stable key set, and a
`reason` drawn from a CLOSED vocabulary declared in each yml, with the sentence kept as
`detail`. Match on `reason`; never on `detail`. This affects `YaraCleanup`, `YaraConsolidateApply`,
`YaraConsolidateStatus`, `YaraConsolidateSummary`, `YaraReport`, `YaraRulesDecode`,
`YaraRulesFromFile`, `YaraScanVerify` and `YaraWipeAllDatasets`.

Two element types deliberately did NOT change, because playbooks splice them where scalars are
expected: `Yara.ConsolidateStatus.eligible_scan_ids` / `.pending_scan_ids` stay lists of plain
strings, and `Yara.Rules.b64` stays a scalar string. A scan_id is data already.

`YaraScanVerify` additionally: `hosts` and `errors` replace the flat `match_rows` map and the
single `error` string; `match_evidence` gained a fourth value `not_attempted`, for the path
where the lifecycle query failed and the match query was therefore never issued; and a
`hostnames` argument that parses to zero hosts is now refused instead of returning a green
verdict over nothing.

`YaraWipeAllDatasets` additionally: `not_attempted` is new, and `lock_taken_over` - the flag
meaning this wipe overrode another run's lock and may have deleted that run's sources
underneath it - is now DECLARED, having been produced but invisible in the output picker.


#### YaraReport — BREAKING: four context paths removed

`Yara.Report.datasets` — one record per dataset — is now the ONE place a fact about a
dataset is carried, and the parallel name lists, the count projection and the rendered blob
that duplicated it are gone. That is the change worth having, but it removes four declared
outputs, and a DT expression against a path that no longer exists resolves to nothing and
reports no error — a silently empty branch, not a failure anyone sees. Check any playbook or
transform that reads `Yara.Report` before installing this.

Removed:

- **`Yara.Report.report`** — the rendered inventory, stored verbatim in context beside the
  identical text in the War Room. The War Room table is now rendered from the result dict,
  and the text is no longer duplicated into context.
- **`Yara.Report.by_type_counts`** — a pure projection of `by_type[<type>].count`. Read that
  instead; it is the same number over the same population.
- **`Yara.Report.legacy`** and **`Yara.Report.newer`** — flat name lists that answered the
  same question as the records beside them. Both are now STATES on the record: filter
  `Yara.Report.datasets` on `state == "legacy"` / `state == "newer"`. The counts are
  unchanged, on `legacy_count` and `newer_count`.
- **`by_type[<type>].by_state`** — published the (name → state) map a second time, leaving a
  reader no way to tell which spelling to trust. `state` is carried on the record only.

Changed in place — same path, different value:

- A pack-output record (`yara_scanner_summary_v<N>_rules_<hash>`, `..._full_...`) carried
  `state` `summary` / `full`; it is now **`pack_output`**, and `type`
  (`consolidated_summary` / `consolidated_full`) is the one place that distinction is made.
- `kind` on those same records is now **`""`** rather than `summary` / `full`. `kind` carries
  the shard vocabulary (`matches` / `scans`) and nothing else, so a branch matching
  `kind == "summary"` now matches nothing.

Added, on the existing `Yara.Report.datasets` records: **`detail`** (the sentence saying what
that record's state means for THAT dataset) and **`remedy`** (the operator action it needs,
`""` where it needs none). Filtering on a non-empty `remedy` is now the supported way to ask
"does anything here need doing". The record's nine keys are also declared individually in
the yml — `datasets.name` through `datasets.remedy` — so the console's output picker shows
the fields, and every key is present on every record even where one does not apply, because
a filter on a sometimes-absent key matches nothing and reports no error. `state` is a closed
vocabulary of nine values, declared in the yml and pinned by tests in both directions.

Also fixed: the `internal` dataset type was documented — in the yml, in the fixed-width CLI
report and in the new War Room table — as "the pack's consolidation lock and run record". It
holds neither, and never has: `yara_scanner_consolidation_lock`,
`yara_scanner_consolidation_runs` and `yara_scanner_cleanup_runs` all fail `YARA_OWNED_RE`
and are dropped before the inventory is built. It is the fallback bucket for a yara-owned
name the naming contract will not parse, so the table was asserting a provenance for a
dataset whose own record says its origin is unknown. Both halves now say the same thing.

## [1.5.0] - 2026-09-05

Released as part of "scanner 3.5.0, pack 1.5.0" and documented here after the fact - the
entry was missed at the time, which left an operator upgrading 1.4.0 to 1.6.0 with no record
of what changed in between.

- **Fleet-scale consolidation.** Both consolidation modes read the whole fleet through one
  wildcard query per source kind instead of one query per host dataset, turning a per-host
  round-trip cost into a constant. A 200-host summary pass went from timing out against the
  900s task limit to finishing in minutes.
- **`max_datasets`** on `YaraConsolidateSummary` and `YaraConsolidateApply`, to drain a large
  backlog in deliberate slices. A bounded pass disables stale-row removal, because a dataset
  it did not read cannot show that a scan was superseded.
- **A summary re-run REFRESHES.** It previously compared scan_id sets and skipped the write
  when they matched, so a target left short by a failed batch stayed wrong for ever. The rows
  read from the host datasets now replace whatever the target holds for those same scans.
- **Full mode retires its sources** once their rows are verified in the ruleset target.
- **Proxy support in the scanner**, including `https://` proxies and TLS-intercepting proxies.

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
