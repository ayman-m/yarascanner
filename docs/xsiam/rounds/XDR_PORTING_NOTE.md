# Fixes on this branch that the XDR edition does not have

Everything here was found and fixed in `xsiam_yara_scanner.py` during the three
acceptance rounds. `xdr_yara_scanner.py` was deliberately **not touched** — the work was
scoped to XSIAM — so this records the drift rather than closing it.

Line numbers are from the XDR file as of this branch and will move.

---

## Confirmed same shape

### 1. FD leak sampling sits after the matched-file early return

```
xdr_yara_scanner.py
  6282   return True, "Scanned and matched"
  6285   self.files_since_fd_check += 1
  6286   if self.files_since_fd_check >= self.fd_check_interval:
```

Identical to the XSIAM defect: the sampler only runs on files that were scanned and did
**not** match, so a ruleset matching everything never samples at all. The increment at
6285 is also unlocked, so it races across workers and drops counts.

XSIAM fix: extracted to `_maybe_sample_fds()`, called before any early return, counter
moved under `lock_counts`, and `fd_samples_taken` / `last_fd_count` added so a healthy
sample is distinguishable from no sample.

### 2. The macOS case-sensitivity probe is uncached

```
xdr_yara_scanner.py
  520   def _is_case_sensitive_fs():
  525       test_file = f"/tmp/CaSe_TeSt_YaRa_{os.getpid()}"
  560       if not _is_case_sensitive_fs():     # inside _get_real_path
  570       if not _is_case_sensitive_fs():
```

Identical to the XSIAM defect: `_get_real_path()` is called per file, so on macOS every
scanned file triggers a create/write/stat/unlink in `/tmp`. Measured on the XSIAM side at
~49,000 cycles for a 48,921-file scan, and it is the scanner's only per-file *write*.

XSIAM fix: answered once and cached for the process under a lock, failures cached too,
with `case_probe_count()` exposed.

### 3. The unreachable cached-dict match path is still present

`isinstance(hit, dict)` still appears once in the XDR file. On the XSIAM side this arm was
enumerated as unreachable — every call site iterates `matches`, which binds only to
`self.rules.match(...)` — and removed, because its decode fallback
(`hx.encode("utf-8", errors="ignore")` on anything `bytes.fromhex` rejected) produced
**wrong bytes silently** rather than raising.

Before deleting it in XDR, repeat the enumeration there rather than assuming: the call
sites differ. And check the XDR test suite — on the XSIAM side six alert offset-cap tests
turned out to be exercising that dead arm, so deleting it broke them and revealed the cap
had never been unit-tested through the production path.

---

## Same pattern, different structure — needs its own analysis

### 4. The upload worker consults its stop flag only on `except Empty`

```
xdr_yara_scanner.py
  3347   except Empty:
  3353       if self.stop_upload_thread:
  3354           flush()
  3355           break
```

This is the shape that caused the XSIAM delivery double-count: a full queue never raises
`Empty`, so the flag is unreachable under exactly the condition it exists for, the join
times out, `stop()` books still-queued items `undelivered`, and the live thread then
delivers some of them into `successful_uploads` — the same items in two buckets.

**Do not port the XSIAM fix blind.** The XDR uploader is not the same code: it batches with
an explicit `flush()`, has `ALERT_REQUEUE_ENABLED` and a rate-limited requeue path, and
line 3622 documents a deliberate window where `stop_upload_thread` stays `False` so
rate-limited batches can still be delivered. Whether the books can actually diverge there
is a separate question that needs its own evidence — ideally the same test that caught it
on the XSIAM side: cancel a scan with a large backlog and check
`ok + failed + undelivered` against the finding count.

---

## Not applicable

Documentation corrections (the worker-cap entry, the queue-saturation reachability note,
the alert-rotation platform split) were made against `docs/xsiam/CAPABILITIES.md`. The XDR
reference already described the worker cap correctly; the other two were not checked
against it.

The worker-throughput rate limit (`WORKER_REPORT_MIN_SECS`) and the governor sampling
counters (`samples_taken`, `secs_since_last_sample`) are XSIAM-only additions. Both are
observability improvements rather than defect fixes, so they are lower priority — though
the throughput one was shipping 94% of a run's events on the XSIAM side, which is worth
measuring on XDR before deciding.
