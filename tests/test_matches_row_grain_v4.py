#!/usr/bin/env python3
"""The lookup-dataset row is ONE ROW PER FILE (schema v4), and stays queryable in XQL.

Grain history: v2 wrote one row per matched string OFFSET, v3 one row per (rule, file)
FINDING. Both repeated every per-file column on every row. Measured on a real /etc scan
(xdr-agent, 2026-08-20): 5,240 finding rows across 2,713 distinct files — 1.93 rules per
matched file — at 838 B/row, 4.19 MiB from ONE endpoint against a platform cap of 50 MB
per lookup dataset. v4 pays the file-level columns once and folds every rule that hit the
file into a `rules` JSON array.

Two properties here are not cosmetic and are the reason this file exists:

  * `string_ids` must be an ARRAY of {id, count}, never an object keyed by the identifier.
    YARA string identifiers begin with '$', and json_extract_scalar(x, "$.$ip") is not a
    valid JSONPath — v3's {"$ip": 50} shape could be stored and never queried.
  * The ALERT grain must NOT move with it. Alerts are one per finding by design and
    CONFIG_ALERT_MAX_PER_SCAN's storm cap is measured against that grain.

The dataset row is also assembled in a `finally`, so a rule raising mid-file (a TOCTOU
OSError on a file deleted mid-scan reaches _write_alerts) cannot cost the whole file's
row — under v3 each row was queued inside the loop and had that property for free.
"""
import json
import os
import sys
import threading
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest  # noqa: E402
import xdr_yara_scanner as m  # noqa: E402


class _LookupStub:
    def __init__(self):
        self.rows = []

    def add(self, record):
        self.rows.append(record)


class _Cfg:
    hostname = "xdr-agent"
    os_info = "Linux-6.8.0-gcp"
    ip_addresses = ["10.128.0.7"]
    scan_id = "xdr-agent_20260820_063001_129174_yara_b451b4336910"
    run_id = "20260820_063001_129174"
    tenant_id = "emea-cxdrp"
    alert_severity = "medium"
    scan_folder = "/etc"


def _uploader(tmp_path=None):
    """A ResultsUploader with only what add_match/add_file_matches touch — no network."""
    ru = m.ResultsUploader.__new__(m.ResultsUploader)
    ru.config = _Cfg()
    ru.hostname, ru.os_info = _Cfg.hostname, _Cfg.os_info
    ru.ip_address, ru.scan_id = _Cfg.ip_addresses[0], _Cfg.scan_id
    ru.date_of_scan = "2026-08-20T06:30:01+00:00"
    ru.log_manager = None
    ru.upload_stats = defaultdict(int)
    ru.upload_thread = None                 # alert channel off: these are dataset tests
    ru._findings_lock = threading.Lock()
    ru._seen_findings = set()
    ru._suppressed_by_rule = {}
    ru._throttled_log = lambda *a, **k: None
    ru.lookup_uploader = _LookupStub()
    return ru


def _hits(sid, literal, n, step=4):
    return [(sid, i * step, literal.encode()) for i in range(n)]


def _one_row(ru):
    assert len(ru.lookup_uploader.rows) == 1, (
        "one matched file must produce exactly one row, got %d" % len(ru.lookup_uploader.rows))
    return ru.lookup_uploader.rows[0]


def test_two_rules_on_one_file_make_one_row():
    ru = _uploader()
    a = ru.add_match("/etc/hosts", "RULE_A", _hits("$a", "alpha", 4))
    b = ru.add_match("/etc/hosts", "RULE_B", _hits("$b", "beta", 2))
    ru.add_file_matches("/etc/hosts", [a, b], file_sha256="ab" * 32)
    row = _one_row(ru)
    assert row["rule_count"] == 2
    assert row["match_total"] == 6
    assert [r["rule"] for r in json.loads(row["rules"])] == ["RULE_A", "RULE_B"]


def test_row_matches_the_declared_schema_exactly():
    """XDR silently SKIPS rows carrying fields the dataset doesn't know about, so a row key
    the schema is missing loses data with no error anywhere."""
    ru = _uploader()
    f = ru.add_match("/etc/hosts", "R", _hits("$a", "x", 1))
    ru.add_file_matches("/etc/hosts", [f], file_sha256="ab" * 32, file_creation_time="2026-01-02")
    row = _one_row(ru)
    assert set(row) == set(m.MATCHES_SCHEMA_V4), (
        "row/schema drift: extra=%s missing=%s"
        % (sorted(set(row) - set(m.MATCHES_SCHEMA_V4)), sorted(set(m.MATCHES_SCHEMA_V4) - set(row))))
    for key, declared in m.MATCHES_SCHEMA_V4.items():
        value = row[key]
        if declared == "number":
            assert isinstance(value, int) and not isinstance(value, bool), (key, value)
        elif declared == "bool":
            assert isinstance(value, bool), (key, value)
        else:
            assert isinstance(value, str), (key, type(value))


def test_v3_only_fields_are_gone():
    """Each is either derivable (run_id/scan_date/date_of_scan live inside scan_id and
    event_timestamp_ms), scan-constant and still on the lifecycle row (scan_folder), or
    folded into `rules`."""
    ru = _uploader()
    f = ru.add_match("/etc/hosts", "R", _hits("$a", "x", 1))
    ru.add_file_matches("/etc/hosts", [f], file_sha256="ab" * 32)
    row = _one_row(ru)
    for gone in ("run_id", "scan_date", "scan_folder", "date_of_scan",
                 "rule", "match_count", "offsets", "strings", "string_ids"):
        assert gone not in row, "%s survived into the v4 row" % gone


def test_string_ids_are_an_array_of_id_count_pairs():
    """The JSONPath constraint. Anything keyed by a '$'-prefixed identifier is unqueryable."""
    ru = _uploader()
    f = ru.add_match("/etc/x", "R", _hits("$ip", "127.0.0.1", 3) + _hits("$cmd", "sh", 1))
    ru.add_file_matches("/etc/x", [f])
    entry = json.loads(_one_row(ru)["rules"])[0]
    assert entry["string_ids"] == [{"id": "$cmd", "count": 1}, {"id": "$ip", "count": 3}]
    for pair in entry["string_ids"]:
        assert set(pair) == {"id", "count"}
        assert not any(k.startswith("$") for k in pair), "a '$' key breaks json_extract_scalar"


def test_anonymous_string_id_is_normalised_not_null():
    """yara reports None for an anonymous string. As a raw key it sorts against str
    (TypeError) and serialises as JSON null; the local alert census already calls it $?."""
    ru = _uploader()
    f = ru.add_match("/etc/x", "R", [(None, 0, b"a"), ("$b", 4, b"b")])
    ru.add_file_matches("/etc/x", [f])
    ids = json.loads(_one_row(ru)["rules"])[0]["string_ids"]
    assert {p["id"] for p in ids} == {"$?", "$b"}


def test_strings_are_distinct_values_not_one_per_offset():
    """v3 stored the same literal once per offset (measured: ["127.0.0.1"] x50). The counts
    already live in match_count and string_ids, so the repetition was pure volume."""
    ru = _uploader()
    f = ru.add_match("/etc/hosts", "R", _hits("$ip", "127.0.0.1", 50))
    ru.add_file_matches("/etc/hosts", [f])
    entry = json.loads(_one_row(ru)["rules"])[0]
    assert entry["strings"] == ["127.0.0.1"]
    assert entry["match_count"] == 50, "the TRUE total must survive the dedupe"
    assert entry["string_ids"] == [{"id": "$ip", "count": 50}]


def test_per_finding_cap_now_bounds_detail_inside_the_row(monkeypatch):
    """CONFIG_LOOKUP_ROWS_PER_FINDING_MAX used to bound how many ROWS one finding produced.
    A finding produces no rows of its own now, so the same number bounds its offsets/strings
    sample inside the file's single row — same knob, one level down."""
    monkeypatch.setattr(m, "CONFIG_LOOKUP_ROWS_PER_FINDING_MAX", 10)
    ru = _uploader()
    f = ru.add_match("/etc/big", "R", [("$s", i, ("lit%d" % i).encode()) for i in range(500)])
    ru.add_file_matches("/etc/big", [f])
    row = _one_row(ru)
    entry = json.loads(row["rules"])[0]
    assert len(entry["offsets"]) == 10
    assert len(entry["strings"]) == 10
    assert entry["match_count"] == 500, "the cap must not touch the reported total"
    assert entry["string_ids"] == [{"id": "$s", "count": 500}], "the census stays uncapped"
    assert entry["truncated"] is True
    assert row["truncated"] is True, "file-level truncated is true when ANY rule was capped"


def test_file_level_truncated_and_severity_aggregate_across_rules(monkeypatch):
    monkeypatch.setattr(m, "CONFIG_LOOKUP_ROWS_PER_FINDING_MAX", 5)
    ru = _uploader()
    small = ru.add_match("/etc/x", "SMALL", _hits("$a", "a", 2))
    big = ru.add_match("/etc/x", "BIG", _hits("$b", "b", 40))
    ru.add_file_matches("/etc/x", [small, big])
    row = _one_row(ru)
    assert [r["truncated"] for r in json.loads(row["rules"])] == [False, True]
    assert row["truncated"] is True
    assert row["match_total"] == 42
    assert row["severity"] == "Medium"          # from alert_severity="medium"
    assert m._max_severity(["Low", "High", "Medium"]) == "High"
    assert m._max_severity(["Low", "bogus"]) == "Low", "an unknown label must not outrank High"


def test_no_findings_queues_no_row():
    ru = _uploader()
    ru.add_file_matches("/etc/x", [])
    ru.add_file_matches("/etc/x", [None])
    assert ru.lookup_uploader.rows == []


def test_offset_grain_stat_still_counts_every_string_hit():
    """upload_stats['total_matches'] is the offset-grain counter the run's books reconcile
    against; folding rows must not change what it counts."""
    ru = _uploader()
    ru.add_match("/etc/x", "A", _hits("$a", "a", 7))
    ru.add_match("/etc/x", "B", _hits("$b", "b", 5))
    assert ru.upload_stats["total_matches"] == 12


# ---------------------------------------------------------------- _write_alerts wiring
class _Inst:
    def __init__(self, offset, data):
        self.offset, self.matched_data = offset, data


class _Str:
    def __init__(self, identifier, instances):
        self.identifier, self.instances = identifier, instances


class _Hit:
    def __init__(self, rule, strings):
        self.rule, self.strings, self.tags, self.meta = rule, strings, [], {}


def _scanner(tmp_path, ru):
    holder = type("_S", (), {})()
    cfg = _Cfg()
    cfg.alert_dir = str(tmp_path / "alert")
    os.makedirs(cfg.alert_dir, exist_ok=True)
    holder.config = cfg
    holder.lock_alert = threading.Lock()
    holder.lock_counts = threading.Lock()
    holder.detection_counts = defaultdict(int)
    holder.total_detections = 0
    holder.rule_source_map = {}
    holder.results_uploader = ru
    return holder


def test_write_alerts_emits_one_row_per_file_and_keeps_the_alert_files(tmp_path):
    ru = _uploader()
    holder = _scanner(tmp_path, ru)
    hits = [_Hit("R1", [_Str("$x", [_Inst(i, b"aa") for i in range(4)])]),
            _Hit("R2", [_Str("$y", [_Inst(i, b"bb") for i in range(2)])])]
    m.YaraScanner._write_alerts(holder, hits, "/tmp/evil.bin", file_sha256="cd" * 32)
    row = _one_row(ru)
    assert row["rule_count"] == 2 and row["match_total"] == 6
    assert row["filename"] == "/tmp/evil.bin"
    assert os.path.exists(os.path.join(holder.config.alert_dir, "R1.txt"))
    assert os.path.exists(os.path.join(holder.config.alert_dir, "R2.txt"))


def test_a_rule_raising_mid_file_still_ships_what_was_gathered(tmp_path):
    ru = _uploader()
    holder = _scanner(tmp_path, ru)

    class _Boom:
        rule, tags, meta = "R2", [], {}

        @property
        def strings(self):
            raise OSError("file vanished mid-scan")

    good = _Hit("R1", [_Str("$x", [_Inst(0, b"aa")])])
    with pytest.raises(OSError):
        m.YaraScanner._write_alerts(holder, [good, _Boom()], "/tmp/evil2.bin")
    row = _one_row(ru)
    assert row["rule_count"] == 1, "detail gathered before the raise was dropped"


# ------------------------------------------------------------------- schema registry
def test_v3_stays_resolvable_for_mid_rollout_datasets():
    """A fleet mid-rollout holds both shapes, and xdr_consolidate resolves a schema by
    version to merge older shards — deleting v3 would strand them."""
    assert m.matches_schema_for("3") is m.MATCHES_SCHEMA_V3
    assert m.matches_schema_for("4") is m.MATCHES_SCHEMA_V4
    assert m.matches_schema_for("99") is m.MATCHES_SCHEMA_V4, "unknown tags fall back to emitted"
    assert m.LOOKUP_SCHEMA_VERSION == m.MATCHES_ROW_SCHEMA_VERSION == "4"


def test_consolidator_knows_the_v4_shape():
    import xdr_consolidate as C
    assert "4" in C.KNOWN_MATCHES_SCHEMA_VERSIONS, (
        "consolidation enumerates shards by known version — v4 shards would never be merged")
    assert C.MATCHES_SCHEMA_V4 == m.MATCHES_SCHEMA_V4, "scanner/consolidator schema drift"


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
