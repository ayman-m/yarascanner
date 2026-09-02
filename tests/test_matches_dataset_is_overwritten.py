#!/usr/bin/env python3
"""The host matches dataset is PERMANENT and OVERWRITTEN, not rotated and appended.

The owner's model: one matches dataset per host, name carrying no scan_id and no month, so
dashboards and the consolidation automations can pin it literally; and at the start of every
scan the scanner clears the rows the PREVIOUS scan left there. What differs between the two
consolidation variants is only what they copy OUT of it — the dataset and the scanner behave
identically either way.

Three properties of the overwrite are pinned here because each one, if it regressed, would be
either silent or unrecoverable:

  NEVER THE CURRENT SCAN. remove_data takes EXACT-VALUE filters only (verified live; see
  xdr_action_center.py:446-449), so "delete everything that is not this scan" is not
  expressible as a filter — the ids must be enumerated by XQL first and the current one
  filtered OUT of that list. A regression that stopped excluding it would delete THIS scan's
  own findings, which is precisely the data nobody has another copy of.

  A MISSING DATASET IS A NO-OP. The first scan on any host has nothing to overwrite. That is
  the ordinary path, not an exception, and it must cost neither an error nor a delete.

  IT FAILS SAFE. Stale rows surviving is recoverable — the next scan tries again, and
  consolidation reads by scan_id anyway. A scan refusing to run because it could not tidy up
  is not recoverable: it is a lost scan of a host, and the tidy-up is the least important
  thing the run does.

Naming is pinned alongside them because the overwrite is what REPLACES rotation on this
dataset. Rotation bounds a dataset's size by minting a new one each month; the overwrite
bounds it by emptying it. Doing both would mean twelve "permanent" datasets a year per host,
each frozen holding its last scan for ever — so rotation now applies to the scans dataset
(append-only, 2 rows/scan, nothing overwrites it) and to that one only.
"""
import json
import os
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import xdr_yara_scanner as m  # noqa: E402

CURRENT = "xdr-agent_20260819_120000_123456_yara_b451b4336910"
STALE_A = "xdr-agent_20260818_090000_000001_yara_b451b4336910"
STALE_B = "xdr-agent_20260817_090000_000002_yara_aaaaaaaaaaaa"


class _Cfg:
    """Only the attributes LookupDatasetUploader.__init__ actually reads."""

    def __init__(self, scan_id=CURRENT, run_id="20260819_120000_123456"):
        self.tenant_id = "emea-cxdrp"
        self.run_id = run_id
        self.hostname = "xdr-agent"
        self.lookup_shard = "endpoint"
        self.scan_id = scan_id
        self.write_dataset = True


class _Log:
    def __init__(self):
        self.uploads = []
        self.errors = []

    def log_upload(self, msg):
        self.uploads.append(str(msg))

    def log_error(self, msg):
        self.errors.append(str(msg))

    def log_system(self, msg):  # pragma: no cover - not exercised here
        pass

    @property
    def all(self):
        return self.uploads + self.errors


class _Resp:
    def __init__(self, status=200, payload=None, text=None):
        self.status_code = status
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload if payload is not None else {})

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _FakeXDR:
    """Routes the scanner's POSTs by endpoint path and records them in call order.

    Order matters as much as content: the overwrite has to be finished before the first
    add_data can be issued, and `calls` is what proves it.
    """

    def __init__(self, existing=(), scan_ids=(), deleted=7,
                 xql_start=None, xql_results=None, remove=None):
        self.existing = list(existing)
        self.scan_ids = list(scan_ids)
        self.deleted = deleted
        self.calls = []          # (kind, request-body)
        self._xql_start = xql_start
        self._xql_results = xql_results
        self._remove = remove
        self._lock = threading.Lock()

    def _record(self, kind, body):
        with self._lock:
            self.calls.append((kind, body))

    def kinds(self):
        with self._lock:
            return [k for k, _ in self.calls]

    def bodies(self, kind):
        with self._lock:
            return [b for k, b in self.calls if k == kind]

    def post(self, url, headers=None, json=None, timeout=None, **kw):  # noqa: A002
        body = (json or {}).get("request") or (json or {}).get("request_data") or {}
        if "get_datasets" in url:
            self._record("get_datasets", body)
            return _Resp(200, {"reply": [{"dataset_name": n} for n in self.existing]})
        if "add_dataset" in url:
            self._record("add_dataset", body)
            self.existing.append(body.get("dataset_name"))
            return _Resp(200, {"reply": {"status": "created"}})
        if "start_xql_query" in url:
            self._record("start_xql_query", body)
            return self._xql_start or _Resp(200, {"reply": "query-id-1"})
        if "get_query_results" in url:
            self._record("get_query_results", body)
            return self._xql_results or _Resp(200, {"reply": {"status": "SUCCESS", "results": {
                "data": [{"scan_id": s, "n": 3} for s in self.scan_ids]}}})
        if "lookups/remove_data" in url:
            self._record("remove_data", body)
            return self._remove or _Resp(200, {"reply": {"deleted": self.deleted}})
        if "lookups/add_data" in url:
            self._record("add_data", body)
            return _Resp(200, {"reply": {"rows added": len(body.get("data") or [])}})
        raise AssertionError(f"unexpected endpoint: {url}")


@pytest.fixture
def live(monkeypatch):
    """A configured tenant with the network faked out, and no auth probe."""
    monkeypatch.setattr(m, "XDR_API_URL", "https://api-emea-cxdrp.xdr.eu.paloaltonetworks.com")
    monkeypatch.setattr(m, "XDR_API_KEY", "k")
    monkeypatch.setattr(m, "XDR_API_ID", "1")
    monkeypatch.setattr(m, "XDR_AUTH_TYPE", "standard")
    monkeypatch.setattr(m, "LOOKUP_FLUSH_POLL_SECS", 0)
    monkeypatch.setattr(m, "LOOKUP_WRITE_JITTER_SECS", 0)

    def _install(api):
        # Patch the SESSION, not requests.post. Every outbound call now goes through the
        # shared session so the adapter that disables verification on the proxy hop is always
        # in the path; patching the module-level requests.post would silently intercept
        # nothing and the fake tenant would never be called.
        monkeypatch.setattr(m, "_http", lambda: api)
        return api

    return _install


def _build(api_installer, api, cfg=None, log=None, start_thread=False, monkeypatch=None):
    """Construct the uploader against the fake tenant.

    The writer thread is stubbed out by default: every test here is about what happens
    BEFORE it exists, and a live daemon thread would race the assertions.
    """
    api_installer(api)
    log = log or _Log()
    if not start_thread:
        m.LookupDatasetUploader._start_thread, _orig = (lambda self: None), m.LookupDatasetUploader._start_thread
    try:
        up = m.LookupDatasetUploader(cfg or _Cfg(), log)
    finally:
        if not start_thread:
            m.LookupDatasetUploader._start_thread = _orig
    return up, log


# --------------------------------------------------------------- naming / rotation
def test_matches_dataset_carries_no_month_suffix(live, monkeypatch):
    """Permanent means permanent: rotation must not mint a new matches dataset each month."""
    monkeypatch.setenv("YARA_LOOKUP_ROTATION", "monthly")
    up, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    assert up.matches_dataset == f"yara_scanner_matches_v{m.LOOKUP_SCHEMA_VERSION}_{up.dataset_shard}", (
        "the matches dataset name is not the permanent per-host form")
    assert "202608" not in up.matches_dataset


def test_scans_dataset_still_rotates(live, monkeypatch):
    """Rotation is not deleted, it is narrowed: scans is append-only and still needs it."""
    monkeypatch.setenv("YARA_LOOKUP_ROTATION", "monthly")
    up, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    assert up.scans_dataset.endswith("_202608"), (
        "rotation was dropped from the scans dataset too - it is append-only (2 rows/scan, "
        "nothing overwrites it) and is the one dataset that still grows without bound")


def test_rotation_none_changes_only_the_scans_dataset(live, monkeypatch):
    monkeypatch.setenv("YARA_LOOKUP_ROTATION", "none")
    up, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    assert not up.scans_dataset.endswith("_202608")
    assert up.matches_dataset == f"yara_scanner_matches_v{m.LOOKUP_SCHEMA_VERSION}_{up.dataset_shard}", (
        "the matches name moved with a setting that no longer governs it")


def test_the_permanent_name_is_stable_across_months(live, monkeypatch):
    """Same host, two runs three months apart -> the SAME matches dataset."""
    monkeypatch.setenv("YARA_LOOKUP_ROTATION", "monthly")
    aug, _ = _build(live, _FakeXDR(), cfg=_Cfg(run_id="20260819_120000_123456"))
    nov, _ = _build(live, _FakeXDR(), cfg=_Cfg(run_id="20261102_010000_000001"))
    assert aug.matches_dataset == nov.matches_dataset
    assert aug.scans_dataset != nov.scans_dataset


# ----------------------------------------------------------- never the current scan
def test_flush_never_removes_the_current_scan_id(live):
    """The current scan_id is present in the dataset AND in the enumeration, and survives."""
    api = _FakeXDR(existing=[f"yara_scanner_matches_v{m.LOOKUP_SCHEMA_VERSION}_xdr_agent_"],
                   scan_ids=[STALE_A, CURRENT, STALE_B])
    # name the dataset exactly as the uploader will, so the probe reports it as pre-existing
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api.existing = [probe.matches_dataset]

    up, log = _build(live, api, cfg=_Cfg())

    removed = [b["filters"][0]["scan_id"] for b in api.bodies("remove_data")]
    assert CURRENT not in removed, (
        "the CURRENT scan's rows were deleted by its own start-of-scan overwrite - this is the "
        "one failure with no other copy of the data")
    assert sorted(removed) == sorted([STALE_A, STALE_B])
    assert up.flush_stats["outcome"] == "ok"
    assert up.flush_stats["rows_deleted"] == 14  # 7 per stale scan_id, from the fake
    assert not log.errors


def test_a_dataset_holding_only_the_current_scan_is_left_alone(live):
    """Re-running the flush must be a no-op, not a delete of everything it finds."""
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[CURRENT])
    up, log = _build(live, api, cfg=_Cfg())
    assert api.bodies("remove_data") == []
    assert up.flush_stats["outcome"] == "no_stale_rows"
    assert not log.errors


def test_without_a_scan_id_nothing_is_deleted(live):
    """No scan_id means no way to tell our rows from anyone's - so delete nothing."""
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A])
    up, _ = _build(live, api, cfg=_Cfg(scan_id=""))
    assert api.bodies("remove_data") == []
    assert api.bodies("start_xql_query") == []
    assert up.flush_stats["outcome"] == "skipped_no_scan_id"


def test_one_remove_call_per_stale_scan_id_each_a_single_exact_filter(live):
    """remove_data is not concurrency-safe and its multi-block form is all-or-nothing, so the
    flush issues one serialised call carrying one exact-value block."""
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A, STALE_B])
    _build(live, api, cfg=_Cfg())

    bodies = api.bodies("remove_data")
    assert len(bodies) == 2
    for b in bodies:
        assert b["dataset_name"] == probe.matches_dataset
        assert len(b["filters"]) == 1, "several scan_ids batched into one all-or-nothing call"
        assert list(b["filters"][0]) == ["scan_id"]


# ------------------------------------------------------------ a missing dataset is a no-op
def test_first_scan_on_a_host_is_a_clean_no_op(live):
    """Nothing exists yet: create it, do not query it, do not delete from it, do not complain."""
    api = _FakeXDR(existing=[], scan_ids=[STALE_A])
    up, log = _build(live, api, cfg=_Cfg())

    assert "add_dataset" in api.kinds(), "the dataset was not created"
    assert api.bodies("start_xql_query") == [], (
        "a dataset we just created was queried for stale rows it cannot contain")
    assert api.bodies("remove_data") == []
    assert up.flush_stats["outcome"] == "skipped_dataset_new"
    assert not log.errors, f"a first-ever scan logged an error: {log.errors}"


def test_a_dataset_that_vanishes_before_the_flush_is_a_no_op_not_an_error(live):
    """Probed as present, gone by the time XQL runs (deleted by retention between the two).

    'Not found' is the platform's own wording for this, and it must read as 'nothing to
    overwrite' rather than as a failure.
    """
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(
        existing=[probe.matches_dataset],
        xql_start=_Resp(400, None, text='{"reply": {"err_msg": "Dataset not found"}}'),
    )
    up, log = _build(live, api, cfg=_Cfg())

    assert api.bodies("remove_data") == []
    assert up.flush_stats["outcome"] == "no_stale_rows"
    assert not log.errors, f"a missing dataset was reported as an error: {log.errors}"


def test_remove_data_on_a_vanished_dataset_is_not_an_error(live):
    """Same again, one step later: gone between the enumeration and the delete."""
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(
        existing=[probe.matches_dataset], scan_ids=[STALE_A],
        remove=_Resp(400, None, text='{"reply": {"err_msg": "Dataset not found"}}'),
    )
    up, log = _build(live, api, cfg=_Cfg())
    assert up.flush_stats["outcome"] == "ok"
    assert up.flush_stats["rows_deleted"] == 0
    assert not log.errors


# ------------------------------------------------------------------------- fail safe
@pytest.mark.parametrize("api_kwargs,where", [
    ({"xql_start": _Resp(403, None, text="The provided API Key does not have the required RBAC permissions")},
     "enumeration (an under-permissioned key: XQL needs Query Center)"),
    ({"xql_results": _Resp(200, {"reply": {"status": "FAIL", "results": {}}})},
     "enumeration (query failed server-side)"),
    ({"remove": _Resp(500, None, text="internal error")},
     "the delete itself"),
])
def test_a_failed_flush_never_stops_the_scan(live, api_kwargs, where):
    """Every failure is logged and swallowed. Stale rows surviving is recoverable; a scan that
    will not run because it could not tidy up is not."""
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A], **api_kwargs)

    up, log = _build(live, api, cfg=_Cfg())

    assert up.flush_stats["outcome"] in ("failed", "partial"), where
    assert log.errors, f"a flush failure in {where} was swallowed silently"
    assert up.flush_stats["error"], "the failure was not recorded for the summary JSON"


def test_the_scan_still_writes_its_rows_after_a_failed_flush(live, monkeypatch):
    """The point of failing safe: rows still land. Runs the REAL writer thread."""
    monkeypatch.setattr(m, "LOOKUP_DATASET_BATCH_SIZE", 1)
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A],
                   remove=_Resp(500, None, text="internal error"))

    up, log = _build(live, api, cfg=_Cfg(), start_thread=True)
    try:
        assert up.upload_thread is not None and up.upload_thread.is_alive()
        up.add({"scan_id": CURRENT, "file_path": "/usr/bin/x"})
        deadline = time.time() + 10
        while time.time() < deadline and not api.bodies("add_data"):
            time.sleep(0.05)
        assert api.bodies("add_data"), "the scan stopped writing because the flush failed"
        assert up.upload_stats["dropped"] == 0
    finally:
        up.stop_flag = True
        up.queue.put(None)
        up.upload_thread.join(timeout=5)


# ------------------------------------------------------------- ordering and reporting
def test_the_overwrite_finishes_before_the_first_row_is_written(live, monkeypatch):
    """A delete that landed after the first add_data would delete this scan's own rows."""
    monkeypatch.setattr(m, "LOOKUP_DATASET_BATCH_SIZE", 1)
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A, STALE_B])

    up, _ = _build(live, api, cfg=_Cfg(), start_thread=True)
    try:
        # Synchronous by construction: by the time the uploader exists, every delete has
        # already landed. Handing the flush to a thread would reintroduce exactly the race
        # this ordering is here to prevent.
        assert len(api.bodies("remove_data")) == 2, (
            "the overwrite had not finished when the uploader was handed back - it is no "
            "longer synchronous, so a delete can now race the scan's own writes")
        up.add({"scan_id": CURRENT, "file_path": "/usr/bin/x"})
        deadline = time.time() + 10
        while time.time() < deadline and not api.bodies("add_data"):
            time.sleep(0.05)
        kinds = api.kinds()
        assert "add_data" in kinds
        assert kinds.index("add_data") > max(i for i, k in enumerate(kinds) if k == "remove_data"), (
            "an add_data POST was issued before the overwrite finished")
    finally:
        up.stop_flag = True
        up.queue.put(None)
        up.upload_thread.join(timeout=5)


def test_the_flush_reports_dataset_scan_ids_rows_and_seconds(live):
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A, CURRENT])
    cfg = _Cfg()
    up, log = _build(live, api, cfg=cfg)

    line = [s for s in log.uploads if "Matches dataset overwrite" in s]
    assert len(line) == 1, f"expected exactly one overwrite report, got {line}"
    line = line[0]
    assert up.matches_dataset in line
    assert STALE_A in line
    assert CURRENT not in line.split("stale scan_ids removed:")[1].split("|")[0]
    assert "rows deleted: 7" in line
    assert re.search(r"\|\s*\d+(\.\d+)?s\b", line), f"no elapsed time in the report: {line}"

    # ...and the same facts machine-readably, for the scan summary JSON.
    assert cfg._matches_flush["dataset"] == up.matches_dataset
    assert cfg._matches_flush["scan_ids_removed"] == [STALE_A]
    assert cfg._matches_flush["rows_deleted"] == 7
    assert isinstance(cfg._matches_flush["seconds"], float)


def test_a_dataset_name_we_did_not_mint_is_never_deleted_from(live, monkeypatch):
    """The shard suffix comes from a hostname. A name that does not round-trip to the shape
    this scanner mints is a name it must not delete rows from, or interpolate into XQL."""
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A])
    api_installer = live
    api_installer(api)
    log = _Log()
    monkeypatch.setattr(m.LookupDatasetUploader, "_start_thread", lambda self: None)
    up = m.LookupDatasetUploader(_Cfg(), log)
    up.matches_dataset = "some_other_teams_dataset"
    up.flush_stats["dataset"] = up.matches_dataset
    up.flush_stats["scan_ids_removed"] = []
    up.flush_stats["rows_deleted"] = 0
    before = len(api.calls)

    up._flush_stale_matches()

    assert api.kinds()[before:] == [], "a foreign dataset was queried or deleted from"
    assert up.flush_stats["outcome"] == "skipped_unrecognised_dataset"


def test_the_flush_gives_up_rather_than_stalling_every_scan_start(live, monkeypatch):
    """It runs on the critical path of every scan on every host, and it is the least important
    thing a run does. A tenant whose polls all hang must cost one bounded delay, not
    max_polls x read_timeout before a single file is scanned."""
    # Already spent when the first poll returns. The poll COUNT is bounded on its own, but
    # each of those polls can itself hang to the read timeout, which is the case the budget
    # exists to bound.
    monkeypatch.setattr(m, "LOOKUP_FLUSH_BUDGET_SECS", 1e-9)
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(
        existing=[probe.matches_dataset],
        # never leaves PENDING: without a budget this polls LOOKUP_FLUSH_MAX_POLLS times
        xql_results=_Resp(200, {"reply": {"status": "PENDING"}}),
    )
    up, log = _build(live, api, cfg=_Cfg())

    assert up.flush_stats["outcome"] == "failed"
    assert "budget" in up.flush_stats["error"]
    assert len(api.bodies("get_query_results")) < int(m.LOOKUP_FLUSH_MAX_POLLS), (
        "the poll loop ran to exhaustion - the budget is not being enforced")
    assert log.errors


def test_the_budget_can_be_disabled(live, monkeypatch):
    """0 means no budget, the same as every other cap knob in this scanner."""
    monkeypatch.setattr(m, "LOOKUP_FLUSH_BUDGET_SECS", 0)
    probe, _ = _build(live, _FakeXDR(), cfg=_Cfg())
    api = _FakeXDR(existing=[probe.matches_dataset], scan_ids=[STALE_A])
    up, log = _build(live, api, cfg=_Cfg())
    assert up.flush_stats["outcome"] == "ok"
    assert up._flush_deadline is None
    assert not log.errors
