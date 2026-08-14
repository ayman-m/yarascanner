#!/usr/bin/env python3
"""Unit tests for the scan-skip predicate — pure, no agent, no network.

The scanner must not scan its own working directory: it writes a multi-megabyte evidence
ZIP and per-rule alert texts there, and the alert texts contain matched strings verbatim,
so scanning them re-matches the rule that produced them.

The subtlety these tests pin is the PATH BOUNDARY. A bare `startswith()` treats the skip
entry as a string prefix rather than a path prefix, which fails in both directions:
  - too broad: "c:\\yara_scanner" also swallows the unrelated sibling
    "c:\\yara_scanner_backup", making it permanently unscannable
  - too narrow: "/opt/yara_scanner/" (with separator) never matches the bare root
    "/opt/yara_scanner" that os.walk yields
Only whole-path-component matching is correct.
"""
import base64
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RULE_B64 = base64.b64encode(b'rule t { strings: $a = "AAAA" condition: $a }').decode()


def _predicate(platform_name, scanner_dir, scan_folder=None):
    """Build a real ScanConfig for `platform_name` and return its skip predicate.

    platform.system() is consulted both by ScanConfig.__init__ (to pick which skip list to
    build) and by the predicate itself (to pick which branch to evaluate), so the patch has
    to stay active across both — hence returning a closure that keeps it applied.

    scan_folder must be a directory that really exists (ScanConfig rejects unusable
    targets), but it has no bearing on the skip lists, which are built from scanner_dir
    plus hardcoded vendor paths. Any real directory works; the tests pass paths that only
    need to be *evaluated*, never opened.
    """
    patcher = mock.patch("platform.system", return_value=platform_name)
    patcher.start()
    try:
        os.environ["YARA_SCANNER_DIR"] = scanner_dir
        import xsiam_yara_scanner as m
        cfg = m.ScanConfig(RULE_B64, scan_folder=scan_folder or os.path.dirname(__file__))

        class _Scanner:
            pass

        holder = _Scanner()
        holder.config = cfg
        holder.scan_active = True

        def check(path):
            with mock.patch("platform.system", return_value=platform_name):
                return m.YaraScanner._is_special_file(holder, path)

        return cfg, check
    finally:
        patcher.stop()
        os.environ.pop("YARA_SCANNER_DIR", None)


# ------------------------------------------------------------------ Windows
def test_windows_skips_own_directory_tree():
    """The baseline that must never regress: the scanner's own tree is skipped."""
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\yara_scanner") is True, "scanner root must be skipped"
    assert skip("C:\\yara_scanner\\evidence") is True
    assert skip("C:\\yara_scanner\\evidence\\evidence_h_1.zip") is True
    assert skip("C:\\yara_scanner\\alert\\SomeRule.txt") is True
    assert skip("C:\\yara_scanner\\logs\\yara_processing_1.log") is True


def test_windows_does_not_swallow_prefix_siblings():
    """Regression: a sibling merely SHARING the name prefix must still be scannable.

    `normalized_path.startswith("c:\\yara_scanner")` is true for
    "c:\\yara_scanner_backup\\evil.dll", so any directory whose name begins with the
    scanner's became a permanent scan blind spot — an evasion vector for anyone able to
    create one. Matching must be on whole path components.
    """
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\yara_scanner_backup\\evil.dll") is False
    assert skip("C:\\yara_scannerX\\payload.exe") is False
    assert skip("C:\\yara_scanner2\\a.txt") is False
    assert skip("C:\\yara_scanner_backup") is False


def test_windows_other_skip_entries_keep_boundary():
    """The same boundary rule must apply to every entry, not just the scanner dir."""
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\ProgramData\\Cyvera\\x.log") is True
    # A sibling of a vendor skip entry is unrelated software and must be scanned.
    assert skip("C:\\ProgramData\\CyveraBackup\\x.log") is False


def test_windows_unrelated_paths_are_scanned():
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\Windows\\System32\\kernel32.dll") is False
    assert skip("C:\\Users\\Public\\doc.docx") is False


def test_windows_custom_scanner_dir_is_skipped():
    """The skip must follow YARA_SCANNER_DIR, not a hardcoded C:\\yara_scanner."""
    cfg, skip = _predicate("Windows", "D:\\custom scan dir")
    assert skip("D:\\custom scan dir\\evidence\\e.zip") is True
    assert skip("D:\\custom scan dir2\\other.dll") is False


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
