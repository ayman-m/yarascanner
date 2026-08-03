# Scan Cancellation — technical detail

Companion to the XDR YARA Scanner Guide. Read this if you need to stop scans at scale, or
to understand why a cancelled scan can still appear to be running.

There are **two ways** to stop a running scan and they behave very differently. Choosing
the wrong one loses data.

---

## 1. The two paths

| | Console **Cancel** | The **`cancel` entry point** |
|---|---|---|
| How | Right-click the action in Action Center | Run the script's `cancel` entry point as a second action |
| Stops the scan | Yes, immediately | Yes, within ~5 s |
| Mechanism | **Hard kill** of the payload process | Cooperative flag file the scan polls |
| Terminal `cancelled` row | **No** | Yes |
| `scan_summary.json` | **No** | Yes |
| Queued alerts / dataset rows | **Discarded** | Drained first |
| Drivable from API / SOAR | **No** | Yes |

**Use the `cancel` entry point** when you want the scan stopped *and* its findings kept.
**Use the console Cancel** when you just need it dead immediately and do not care about
what it had found so far.

## 2. Console Cancel hard-kills the payload

Measured on agent 9.2.0.90, one Cancel against a three-endpoint scan. One endpoint had
already finished; two were mid-scan.

| | mid-scan #1 | mid-scan #2 | already finished |
|---|---|---|---|
| action status | `ABORTED` | `ABORTED` | `COMPLETED_SUCCESSFULLY` |
| payload process | **killed** | **killed** | exited normally |
| `"cancelled by operator"` in log | no | no | n/a |
| cleanup / finalisation | **none** | **none** | full |
| `scan_summary_*.json` | **not written** | **not written** | written |
| last log line | mid-walk, no cleanup | mid-walk, no cleanup | normal completion |

Uploads were succeeding right up to termination (`Lookup batch ok (170 rows)`), so the
process was healthy and killed mid-flight — not failing.

> Cortex documentation states that once an action is *In Progress* it *"cannot be canceled
> from the management console."* **That statement is about agent upgrades and does not
> apply to script executions.** For scripts, the console Cancel does stop them — by killing
> the process.

## 3. The consequence: orphaned lifecycle rows

A killed scan never writes a terminal row, so its lifecycle is stuck **permanently**:

```
finished normally   initiated -> completed   (210,170 files)
console-cancelled   initiated                 <- stuck forever
console-cancelled   initiated -> running      <- stuck forever
```

Any dashboard widget counting *"scans in progress"* or *"initiated vs completed"* will show
console-cancelled scans as **running indefinitely**, long after the process is dead.

**This is the most likely reason someone reports that cancellation "doesn't work".** The
action status says `ABORTED`, but the dashboard — where scan state actually lives — says
still running. Both observations are correct: the process died, the record never closed.

If you use console Cancel, expect to clean up orphaned rows, or prefer the `cancel` entry
point which closes the record properly.

## 4. Why the scanner cannot fix this

Writing a terminal row on console Cancel is **impossible by construction**:

- The agent runs Action Center scripts on a worker thread named `script_thread`, not the
  main thread. `signal.signal()` therefore raises *"signal only works in main thread of the
  main interpreter"* on both Windows and Linux — **no signal handler can be installed**.
- Windows termination is `TerminateProcess`, which no handler could intercept even if one
  could be installed.

There is no cleanup hook available. This is why the cooperative `cancel` entry point exists.

## 5. How the `cancel` entry point works

```
operator → Action Center → run the script's `cancel` entry point (a SECOND action)
             ↓
   agent starts a second payload process
             ↓
   it writes <scanner_dir>/control/cancel.flag        ← this is the "signal"
             ↓
   the running scan's watcher polls for it every 5 s
             ↓
   scan stops, drains alerts + dataset rows, writes a terminal `cancelled` row
```

The two processes never communicate directly. The filesystem is the only namespace both can
reach, which is why a flag file is not a lazy design but the only one available.

**Measured:** a cancel delivered mid-scan stopped both workers in the **same millisecond**
the flag was detected, and the process exited **2.0 s** later having written
`Scan cancelled by operator: 12,316 files scanned | 56 matches found` and its summary.

The cancel command also reports whether it found a live scan:

```
Cancel signal delivered (C:\yara_scanner\control\cancel.flag) | scanner running: yes | scan_id=...
```

## 6. Scale: cancelling a fleet

Both paths have a cost at fleet scale, and it is worth knowing which you are paying:

- **Console Cancel** removes endpoints still `Pending` from the queue and kills those
  already running. One gesture, but every running scan loses its in-flight findings.
- **The `cancel` entry point** must be *delivered* to each endpoint as a second action,
  through the same Action Center queue that is already busy with the scan you are stopping.
  Findings are preserved, but cancellation is paced like any other fleet action.

There is **no public API to cancel an action**. The cancel/abort endpoints live under
`/api/webapp/`, the console's private backend, which requires an interactive MFA session
and is not supported for automation. The `cancel` entry point is therefore the only
API-drivable stop mechanism, which is what makes it usable from SOAR playbooks.

## 7. Quick reference

| You want to… | Do this |
|---|---|
| Stop a scan and keep its findings | `cancel` entry point |
| Stop a scan immediately, findings not important | Console Cancel |
| Stop scans from a playbook or script | `cancel` entry point (only option) |
| Stop endpoints that have not started yet | Console Cancel (removes them from the queue) |
| Understand why a "cancelled" scan still shows as running | §3 — orphaned lifecycle rows |
