#!/usr/bin/env python3
"""Unit tests for HostCleanup — end-of-run removal of a scan's on-host working files.

Real filesystem, real tmp directories: this is filesystem-manipulation logic, so an
integration-style test against real files is more honest than mocking os/shutil.
"""
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xdr_yara_scanner import HostCleanup  # noqa: E402


class FakeConfig:
    """Just enough of ScanConfig for HostCleanup — real paths under a tmp scanner_dir."""

    def __init__(self, root, run_id="20260810_050000_123456"):
        self.scanner_dir = root
        self.run_id = run_id
        self.logs_dir = os.path.join(root, "logs")
        self.alert_dir = os.path.join(root, "alert")
        self.evidence_dir = os.path.join(root, "evidence")
        self.failed_rules_dir = os.path.join(root, "failed_rules")
        for d in (self.logs_dir, self.alert_dir, self.evidence_dir, self.failed_rules_dir):
            os.makedirs(d, exist_ok=True)
        self.create_alerts = True
        self.write_dataset = True


@pytest.fixture
def cfg():
    root = tempfile.mkdtemp(prefix="hostcleanup_")
    yield FakeConfig(root)
    shutil.rmtree(root, ignore_errors=True)


def _touch(path, content="x"):
    with open(path, "w") as f:
        f.write(content)


def _seed_run_artifacts(cfg, run_id=None):
    """Write a full set of this run's files, matching real scanner output shape."""
    rid = run_id or cfg.run_id
    for kind in ("system", "upload", "yara_processing", "statistics", "alerts", "scan_errors"):
        _touch(os.path.join(cfg.logs_dir, "%s_%s.log" % (kind, rid)))
    summary_path = os.path.join(cfg.logs_dir, "scan_summary_%s.json" % rid)
    _touch(summary_path, '{"outcome":"completed"}')
    _touch(os.path.join(cfg.alert_dir, "MatchRule.txt"))
    _touch(os.path.join(cfg.evidence_dir, "evidence_host_%s.zip" % rid))
    _touch(os.path.join(cfg.evidence_dir, "file_mapping.txt"))
    _touch(os.path.join(cfg.failed_rules_dir, "skipped_rule_x_cuckoo.yar"))
    return summary_path


# --------------------------------------------------------------- should_run gate
def test_off_never_runs():
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "off", "summary"
    ok, reason = hc.should_run(shortfall="", delivery_enabled=True)
    assert ok is False
    assert "off" in reason.lower() or "disabled" in reason.lower()


def test_on_delivery_blocked_by_shortfall():
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "on_delivery", "summary"
    ok, reason = hc.should_run(shortfall="alerts: 4 of 4 NOT delivered", delivery_enabled=True)
    assert ok is False
    assert "delivery" in reason.lower()


def test_on_delivery_runs_when_clean():
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "on_delivery", "summary"
    ok, reason = hc.should_run(shortfall="", delivery_enabled=True)
    assert ok is True


def test_on_delivery_refuses_when_no_delivery_channel_enabled():
    # Both create_alerts and write_dataset off: there IS no "delivery" to gate on, so the
    # local copy is the only copy. on_delivery must not treat "nothing attempted" as
    # "everything delivered" - that would wipe the only record of the scan's findings.
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "on_delivery", "summary"
    ok, reason = hc.should_run(shortfall="", delivery_enabled=False)
    assert ok is False
    assert "delivery" in reason.lower()


def test_always_ignores_shortfall():
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "always", "summary"
    ok, _ = hc.should_run(shortfall="alerts: 4 of 4 NOT delivered", delivery_enabled=True)
    assert ok is True


def test_always_ignores_missing_delivery_channel_too():
    # "always" is the explicit opt-out of the delivery gate entirely - by design it also
    # overrides the no-channel-enabled refusal above.
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "always", "summary"
    ok, _ = hc.should_run(shortfall="", delivery_enabled=False)
    assert ok is True


def test_unknown_mode_treated_as_off():
    hc = HostCleanup.__new__(HostCleanup)
    hc.mode, hc.keep = "sometimes", "summary"
    ok, reason = hc.should_run(shortfall="", delivery_enabled=True)
    assert ok is False
    assert "sometimes" in reason or "unknown" in reason.lower()


# --------------------------------------------------------------------- run(): removal
def test_run_keep_summary_removes_everything_else(cfg):
    summary_path = _seed_run_artifacts(cfg)
    hc = HostCleanup(cfg, mode="always", keep="summary")
    removed, errors = hc.run(summary_path)

    assert errors == []
    assert os.path.isfile(summary_path), "summary must survive under keep=summary"
    remaining_logs = os.listdir(cfg.logs_dir)
    assert remaining_logs == [os.path.basename(summary_path)]
    assert os.listdir(cfg.alert_dir) == []
    assert os.listdir(cfg.evidence_dir) == []
    assert os.listdir(cfg.failed_rules_dir) == []


def test_run_keep_nothing_removes_summary_too(cfg):
    summary_path = _seed_run_artifacts(cfg)
    hc = HostCleanup(cfg, mode="always", keep="nothing")
    removed, errors = hc.run(summary_path)

    assert errors == []
    assert not os.path.exists(summary_path)
    assert os.listdir(cfg.logs_dir) == []


def test_run_keep_evidence_preserves_evidence_dir(cfg):
    summary_path = _seed_run_artifacts(cfg)
    hc = HostCleanup(cfg, mode="always", keep="evidence")
    removed, errors = hc.run(summary_path)

    assert errors == []
    assert os.path.isfile(summary_path)
    assert sorted(os.listdir(cfg.evidence_dir)) == \
        sorted(["evidence_host_%s.zip" % cfg.run_id, "file_mapping.txt"])
    assert os.listdir(cfg.alert_dir) == []          # "remove the REST" - alerts still go
    assert os.listdir(cfg.failed_rules_dir) == []


def test_run_never_touches_a_different_runs_logs(cfg):
    # logs_dir holds retained history from OTHER runs (LOG_KEEP_SCANS). Cleaning up THIS
    # run must never remove another run's files - that would silently break retention.
    other_summary = _seed_run_artifacts(cfg, run_id="20260101_010101_000000")
    this_summary = _seed_run_artifacts(cfg, run_id=cfg.run_id)

    hc = HostCleanup(cfg, mode="always", keep="summary")
    hc.run(this_summary)

    assert os.path.isfile(other_summary), "a different run's summary must survive untouched"
    other_logs = [f for f in os.listdir(cfg.logs_dir) if "20260101_010101_000000" in f]
    assert len(other_logs) == 7, "all 6 other-run logs + its summary must be untouched"


def test_run_never_removes_rule_cache(cfg):
    # rule_cache is a cross-run performance cache, not this run's data, and is already
    # self-capped elsewhere (RULE_CACHE_MAX_FILES). HostCleanup must never touch it.
    cache_dir = os.path.join(cfg.scanner_dir, "rule_cache")
    os.makedirs(cache_dir, exist_ok=True)
    _touch(os.path.join(cache_dir, "rules_abc123.yarac"))

    summary_path = _seed_run_artifacts(cfg)
    hc = HostCleanup(cfg, mode="always", keep="nothing")
    hc.run(summary_path)

    assert os.path.isfile(os.path.join(cache_dir, "rules_abc123.yarac"))


def test_run_recreates_wiped_directories_empty(cfg):
    summary_path = _seed_run_artifacts(cfg)
    hc = HostCleanup(cfg, mode="always", keep="summary")
    hc.run(summary_path)

    for d in (cfg.alert_dir, cfg.evidence_dir, cfg.failed_rules_dir):
        assert os.path.isdir(d), "%s must still exist (empty) after cleanup" % d


def test_run_collects_removal_errors_without_raising(cfg, monkeypatch):
    summary_path = _seed_run_artifacts(cfg)
    hc = HostCleanup(cfg, mode="always", keep="summary")

    real_remove = os.remove

    def flaky_remove(path):
        if path.endswith("system_%s.log" % cfg.run_id):
            raise PermissionError("in use")
        return real_remove(path)

    monkeypatch.setattr(os, "remove", flaky_remove)
    removed, errors = hc.run(summary_path)

    assert len(errors) == 1
    assert "system_" in errors[0]
    # everything else still got removed despite the one failure
    assert not os.path.isfile(os.path.join(cfg.logs_dir, "upload_%s.log" % cfg.run_id))


def test_run_returns_empty_when_summary_path_missing(cfg):
    # Safety check: never run destructive cleanup off an unverified/never-written summary.
    hc = HostCleanup(cfg, mode="always", keep="summary")
    fake_path = os.path.join(cfg.logs_dir, "scan_summary_nonexistent.json")
    removed, errors = hc.run(fake_path)
    assert removed == [] and errors == []


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
