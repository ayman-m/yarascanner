#!/usr/bin/env python3
"""Unit tests for alert-text offset sampling — pure, no agent, no network.

The local alert/<rule>.txt rendered EVERY matched offset, ~95 bytes each. A single rule
matching Windows event logs produced 2.4M offsets and a 220 MB file on the scanned host.

The product decision this encodes: individual offsets are not what an analyst works from.
Which host, which rule, WHICH STRING IN THE RULE, and which file are — so the census
(per-string-ID hit counts) is written in full and uncapped, while the offsets themselves
are sampled. The tenant already applies the same deal via MAX_MATCH_SAMPLES_PER_FINDING.
"""
import os
import sys
import threading
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import xsiam_yara_scanner as m  # noqa: E402


class _StubUploader:
    """Swallows match uploads — delivery is not what these tests are about."""

    def __init__(self):
        self.calls = []

    def add_match(self, *a, **kw):
        self.calls.append((a, kw))


class _StubConfig:
    def __init__(self, tmpdir):
        self.alert_dir = os.path.join(tmpdir, "alert")
        self.alert_severity = "low"
        os.makedirs(self.alert_dir, exist_ok=True)


def _writer(tmpdir):
    """Duck-typed stand-in exposing exactly what _write_alerts touches."""
    holder = type("_S", (), {})()
    holder.config = _StubConfig(tmpdir)
    holder.lock_alert = threading.Lock()
    holder.lock_counts = threading.Lock()
    holder.detection_counts = defaultdict(int)
    holder.total_detections = 0
    holder.rule_source_map = {}
    holder.results_uploader = _StubUploader()
    return holder


def _hit(rule, pairs):
    """Build a cached-dict-shaped YARA hit. pairs = [(offset, string_id, text), ...]."""
    return {
        "rule": rule,
        "tags": [],
        "meta": {},
        "strings": [(off, sid, text.encode().hex()) for off, sid, text in pairs],
    }


def _alert_text(holder, rule):
    p = os.path.join(holder.config.alert_dir, f"{rule}.txt")
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def test_offsets_are_capped_but_census_is_complete(tmp_path, monkeypatch):
    """The cap bounds rendered offsets; per-string-ID counts stay exact and uncapped.

    This is the whole design in one assertion: an analyst still learns that $ps fired
    1,000 times and $enc 500 times, without the file carrying 1,500 offset stanzas.
    """
    monkeypatch.setattr(m, "MAX_ALERT_OFFSETS_PER_FINDING", 10)
    holder = _writer(str(tmp_path))
    pairs = ([(i, "$ps", "powershell") for i in range(1000)]
             + [(i, "$enc", "-enc") for i in range(500)])
    m.YaraScanner._write_alerts(holder, [_hit("R", pairs)], "/tmp/evil.evtx")

    text = _alert_text(holder, "R")
    assert text.count("Offset:") == 10, "rendered offsets must respect the cap"
    assert "$ps=1000" in text, "census must report the TRUE uncapped count for $ps"
    assert "$enc=500" in text, "census must report the TRUE uncapped count for $enc"
    assert "1490" in text, "omission note must state how many were dropped"


def test_small_finding_is_unchanged(tmp_path, monkeypatch):
    """Findings under the cap must render in full, with no omission note.

    99.75% of real findings are small; the bound must be invisible to them.
    """
    monkeypatch.setattr(m, "MAX_ALERT_OFFSETS_PER_FINDING", 50)
    holder = _writer(str(tmp_path))
    pairs = [(i, "$a", "mimikatz") for i in range(6)]
    m.YaraScanner._write_alerts(holder, [_hit("Mimikatz", pairs)], "/tmp/x.dll")

    text = _alert_text(holder, "Mimikatz")
    assert text.count("Offset:") == 6
    assert "omitted" not in text.lower()
    assert "$a=6" in text


def test_file_size_tracks_cap_not_offset_count(tmp_path, monkeypatch):
    """The artefact must stop growing with offset count — that is the point."""
    monkeypatch.setattr(m, "MAX_ALERT_OFFSETS_PER_FINDING", 20)
    holder = _writer(str(tmp_path))
    small = [(i, "$a", "x") for i in range(20)]
    big = [(i, "$a", "x") for i in range(200000)]
    m.YaraScanner._write_alerts(holder, [_hit("Small", small)], "/tmp/a")
    m.YaraScanner._write_alerts(holder, [_hit("Big", big)], "/tmp/b")

    s = os.path.getsize(os.path.join(holder.config.alert_dir, "Small.txt"))
    b = os.path.getsize(os.path.join(holder.config.alert_dir, "Big.txt"))
    assert b < s * 2, (
        f"200,000 offsets produced {b}B vs {s}B for 20 - size still tracks offset count"
    )


def test_identity_fields_always_present(tmp_path, monkeypatch):
    """Which rule / which file / which hash must never be sampled away."""
    monkeypatch.setattr(m, "MAX_ALERT_OFFSETS_PER_FINDING", 1)
    holder = _writer(str(tmp_path))
    pairs = [(i, "$a", "hit") for i in range(500)]
    m.YaraScanner._write_alerts(holder, [_hit("R", pairs)], "/tmp/target.dll",
                                file_sha256="a" * 64)

    text = _alert_text(holder, "R")
    assert "/tmp/target.dll" in text
    assert "a" * 64 in text
    assert "R" in text


def test_cap_of_zero_means_unbounded(tmp_path, monkeypatch):
    """0 is the documented escape hatch for anyone who really wants every offset."""
    monkeypatch.setattr(m, "MAX_ALERT_OFFSETS_PER_FINDING", 0)
    holder = _writer(str(tmp_path))
    pairs = [(i, "$a", "hit") for i in range(300)]
    m.YaraScanner._write_alerts(holder, [_hit("R", pairs)], "/tmp/x")

    assert _alert_text(holder, "R").count("Offset:") == 300


def test_return_value_still_reports_true_total(tmp_path, monkeypatch):
    """Sampling the FILE must not change what the merged alert event reports.

    _write_alerts' return feeds the single alert event scan_file emits; if the cap leaked
    into it, the tenant would under-report hits.
    """
    monkeypatch.setattr(m, "MAX_ALERT_OFFSETS_PER_FINDING", 5)
    holder = _writer(str(tmp_path))
    pairs = [(i, "$a", "hit") for i in range(777)]
    out = m.YaraScanner._write_alerts(holder, [_hit("R", pairs)], "/tmp/x")

    assert out["total_string_matches"] == 777
    assert out["detections"][0]["match_count"] == 777


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
