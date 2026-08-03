# Release Notes

Every released version of `xdr_yara_scanner.py` and its companion scripts. Each entry
records what changed and **why**, so you can decide whether a release is worth taking.

The guides in `docs/guides/` describe the **current** version only. Anything about how a
behaviour used to work, or the testing behind a change, lives here.

**Which version am I running?** Read `scanner_version` in `scan_summary_<run_id>.json`, or
the `VERSION` line at the top of `yara_processing_<run_id>.log`.

Versioning is semantic: **MAJOR** breaks something, **MINOR** adds capability, **PATCH**
fixes without changing behaviour you rely on.

---

## v2.0.0 — 2026-08-03

First formally released version. Everything below is relative to the unversioned builds
shared before this date.

### Upgrading

**Drop-in.** Edit the three credential lines and the `CUSTOMER CONFIG` block, re-upload to
the script library, done. Retired options are still accepted and translated, so existing
playbooks and scheduled jobs keep running unchanged:

| Old option | Now |
|---|---|
| `throttle_mode=off` | `cpu_guarantee=none` |
| `throttle_mode=script` or `os` | `cpu_guarantee=headroom` |
| `cpu_high_threshold`, `cpu_critical_threshold`, `max_pause_secs` | accepted, value ignored |

Existing lookup datasets are unaffected — the `_v2` schema is unchanged.

### New — CPU impact control that can be stated and verified

Replaces the previous `throttle_mode = script | os | off` design. You now choose a
guarantee rather than a threshold:

- **`headroom`** (default) — always leave N% of the host free; the scan's share adapts to
  whatever else is running.
- **`budget`** — never exceed N% of the host, whatever else is running.
- **`none`** — no governing.

Constants: `CONFIG_CPU_GUARANTEE`, `CONFIG_CPU_HEADROOM_PCT` (30), `CONFIG_CPU_BUDGET_PCT`
(25), `CONFIG_CPU_FLOOR_PCT` (5).

**Why the old design went.** It watched *system-wide* CPU and paused the scan above a
threshold, which meant it punished itself for load it did not cause and kept pausing while
that load persisted. Measured on 8-core Linux: **285 s of a 347 s scan spent parked**, worst
case **65.9× slower** than unthrottled — operators experienced a scan that never finished.
It also bought nothing: across 2, 4 and 8 cores under saturating load, every mode protected
the competing workload to within **−3% to +1%** of no throttling at all. The `os` tier was
worse still, starving on a busy host (**252 s vs 77 s** for the same work).

The new design does not claim to protect the host either — no self-governed throttle
meaningfully can. What it adds is a share you can state before the scan, a floor that
guarantees the scan finishes, and telemetry proving the bound held.

### New — `xdr_data_management.py`

Standalone script to stop lookup datasets accumulating forever. Reports an inventory, and
deletes rotated months or legacy-schema datasets on an age you choose. Dry run unless
`--yes`; five safety rails including never touching the current month.

**No scan depends on it.** The scanner creates and writes its own datasets; if this never
runs, datasets grow but every scan still succeeds.

### Changed — worker default stays at 2

`CONFIG_WORKERS` is configurable and the old hard cap of 2 is gone, but 2 remains the
default because that is what the measurements support: on 8-core Linux over 93k files,
**2 workers = 71 s, 4 = 93 s, 8 = 101 s**. Scanning is disk-bound, so more concurrent
readers cause seek contention rather than useful overlap. Raise it only if you measure a
gain on your storage.

### Fixed — cancellation exited up to 55 s after it stopped scanning

A cancelled scan stopped its workers promptly but then took up to 55 s to exit, because the
directory walk used `os.walk`, which yields a whole directory tree level at a time and could
not be interrupted mid-level. Replaced with an explicit cancellable walk.

Measured on the same `C:\` scan: workers stopped in the **same millisecond** as the request
(was +4.45 s), cleanup started the same millisecond (was +55.0 s), process exited **+2.02 s**
(was +55.0 s). A 46-directory regression corpus with symlinks produced identical results
before and after.

### Fixed — a scan that delivered nothing reported success

If every alert failed to upload — revoked key, missing permission, unreachable tenant — the
scan reported `outcome: completed`, `undelivered: 0`, and wrote no error log. The only trace
was one line in the upload log, so an operator would reasonably conclude the alerts landed.

Cause was a naming trap: `undelivered` counts only items **never attempted**, while items
attempted and rejected went to `failed_uploads`. Both are real loss; only one was named like
it.

Scans now report the shortfall in three places — the `SCAN_RESULT` line, an ERROR in
`scan_errors_<run_id>.log`, and a `delivery_shortfall` field in the summary JSON. Read-timeout
batches count as *not* delivered: the server may have committed them, but "may have" is not
evidence.

### Fixed — running the script directly printed nothing

The CLI path exited 0 having reported nothing at all. Anyone validating the scanner outside
Action Center — a scheduled task, CI, a customer smoke test — got silence. Now prints
`SCAN_RESULT: ...`, the same prefix the Action Center path uses.

### Fixed — scanning a path under a platform skip-list failed silently

A scan targeting a directory beneath an excluded path (`/tmp`, `/proc`, `/private/tmp`)
reported "0 files scanned" with no reason. It now warns explicitly, naming the path and the
exclusion that caught it.

### Added — versioning

The script carries `__version__`, reports it in `scan_summary_<run_id>.json` as
`scanner_version`, and logs it at the start of every run. A shared copy of the file now
identifies itself.

### Known limitations

These are platform behaviours, not defects in the scanner. They are documented so you are
not surprised by them.

- **The console's Cancel hard-kills the payload.** A scan stopped that way writes no terminal
  row and no summary, so dashboards show it as running indefinitely. Use the `cancel` entry
  point to stop a scan and keep its findings. The scanner cannot fix this: the agent runs
  scripts off the main thread, so no signal handler can be installed.
- **One lookup dataset per endpoint, not one for the estate.** `lookups/add_data` is not
  concurrency-safe — two endpoints writing one dataset lose rows silently (~2 of 8 batches at
  8-way concurrency). Per-writer sharding is the workaround. Bucket hosts with a literal
  `CONFIG_LOOKUP_SHARD` label to reduce the count.
- **Windows agents cap payloads at 2 CPU cores**, so on an 8-core host the scanner cannot
  exceed ~25% regardless of configuration.
- **Rule compatibility is set by the agent's libyara build**, not by the agent version.
  Modules beyond `pe`, `elf`, `math`, `hash` and `time` are unavailable, and Windows and
  Linux agents differ. A rule compiling on your workstation proves nothing about the agent.
- **There is no public API to upload a script to the library.** The initial upload is a
  one-time console action; everything after it is API-drivable.
