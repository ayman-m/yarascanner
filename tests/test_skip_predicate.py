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

    os.makedirs is stubbed out for the duration of construction. ScanConfig eagerly creates
    its working tree, and scanner_dir here is a foreign-platform path — so on a POSIX host
    "C:\\yara_scanner" is not a drive reference but a perfectly legal single directory NAME
    containing backslashes, and running these tests literally created 37 junk directories in
    the repo root (invisible to git status: their contents are all *.log, which .gitignore
    covers, and git does not track empty dirs). It also made /opt/yara_scanner raise
    PermissionError, which is why these tests briefly used tmp-path substitutes instead of
    the real platform defaults. Stubbing the call fixes both: nothing touches the
    filesystem, and the REAL default paths can be asserted against.
    """
    patcher = mock.patch("platform.system", return_value=platform_name)
    patcher.start()
    try:
        os.environ["YARA_SCANNER_DIR"] = scanner_dir
        import xsiam_yara_scanner as m
        with mock.patch("os.makedirs"):
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


def test_windows_cyvera_anywhere_under_the_drive_is_skipped():
    """Cyvera (the Cortex/Traps agent) must be skipped wherever it is installed on C:.

    Regression: the old win_skip_patterns matcher ("C:\\*\\cyvera\\*") could never fire -
    it split "c:" off the pattern via string ops, but compared against a path that had
    already had its drive letter stripped by os.path.splitdrive, so "c:" could never be
    found; and "*" was compared as a literal string, not a wildcard. Confirmed by direct
    execution: the matcher returned False for every path tested, including the one
    hardcoded skip entry (C:\\ProgramData\\Cyvera) it was meant to generalise.
    """
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\ProgramData\\Cyvera\\log.txt") is True, "the hardcoded case must work"
    assert skip("C:\\Program Files\\Cyvera\\agent.exe") is True, "install elsewhere on C: too"
    assert skip("C:\\Program Files (x86)\\Cyvera\\agent.dll") is True


def test_windows_cyvera_prefix_sibling_not_swallowed():
    """The new cyvera check must not repeat the earlier prefix-over-match bug."""
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\Program Files\\CyveraBackup\\x.log") is False
    assert skip("C:\\Program Files\\NotCyvera\\x.log") is False


def test_windows_cyvera_coverage_is_not_a_universal_evasion_vector():
    """Regression: an unscoped '/cyvera/' fragment (any path, any drive, any depth) turns
    ANY directory literally named "cyvera" into a permanent blind spot - including ones an
    unprivileged actor can create in a world-writable location. Caught by adversarial
    review of the first fix: C:\\Users\\cyvera, C:\\Users\\Public\\cyvera and C:\\Temp\\cyvera
    were all wrongly skipped, on every drive letter, not just C:. Coverage must stay
    anchored to real, admin-only vendor install roots, matching the security model of every
    other win_skip_folder entry - not "anywhere a directory happens to be named cyvera".
    """
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\Users\\cyvera\\Documents\\resume.docx") is False, \
        "a real user named cyvera is not the security agent"
    assert skip("C:\\Users\\Public\\cyvera\\payload.exe") is False, \
        "world-writable location must not become an evasion vector"
    assert skip("C:\\Temp\\cyvera\\evil.dll") is False
    assert skip("D:\\cyvera\\x") is False, "coverage is C: only, per the vendor's real install"


# ------------------------------------------------------------------ Darwin app bundles
def test_darwin_app_bundle_contents_are_skipped():
    """Regression: '.app/Contents/Frameworks/' etc. are suffix-anchored to a bundle NAME
    ("Slack.app/Contents/..."), so the character before ".app" is always the bundle name's
    last letter, never a path separator. Requiring a leading "/" - correct for every other
    relative entry - meant these three never matched, before OR after the first fix; only
    the reason changed. Still uncaught by the first fix's 12 tests.
    """
    cfg, skip = _predicate("Darwin", "/usr/local/yara_scanner")
    assert skip("/Applications/Slack.app/Contents/Frameworks/Electron Framework") is True
    assert skip("/Applications/Docker.app/Contents/Resources/bin/docker") is True
    assert skip("/Applications/MyApp.app/Contents/_CodeSignature/CodeResources") is True


def test_windows_scanner_dir_still_skipped_after_pattern_removal():
    """win_skip_patterns is retired entirely; win_skip_folder alone must still cover it."""
    cfg, skip = _predicate("Windows", "C:\\yara_scanner")
    assert skip("C:\\yara_scanner\\evidence\\e.zip") is True
    assert skip("C:\\yara_scanner\\alert\\R.txt") is True


# ------------------------------------------------------------------ Linux
def test_linux_skips_own_directory_and_system_paths():
    cfg, skip = _predicate("Linux", "/opt/yara_scanner")
    assert skip("/opt/yara_scanner/evidence/e.zip") is True
    assert skip("/sys/kernel/x") is True
    assert skip("/proc/1/status") is True


def test_linux_scanner_dir_bare_root_is_skipped():
    """Regression: the root os.walk yields has NO trailing separator, but the skip entry
    was built WITH one ("/opt/yara_scanner/"), so startswith() failed on the root itself.
    """
    cfg, skip = _predicate("Linux", "/opt/yara_scanner")
    assert skip("/opt/yara_scanner") is True, "hardcoded entry's bare root"
    assert skip("/opt/yara_scanner/evidence") is True, "and its subdirectories"


def test_linux_does_not_case_fold():
    """Linux filesystems are typically case-sensitive; matching must stay case-exact.

    This guards against the Darwin case-folding fix leaking into the Linux branch, which
    would be wrong there - the fixes address different platforms' actual filesystem
    semantics, not a shared behaviour.
    """
    cfg, skip = _predicate("Linux", "/opt/yara_scanner")
    assert skip("/OPT/YARA_SCANNER/evidence/e.zip") is False


# ------------------------------------------------------------------ Darwin
def test_darwin_absolute_entries_skip_regardless_of_case():
    """Regression: APFS is case-insensitive by default, but neither side was case-folded.

    A scan target or intermediate path segment typed in different case than the hardcoded
    entries silently defeated the skip on the real filesystem, where the two paths are the
    same directory.
    """
    cfg, skip = _predicate("Darwin", "/usr/local/yara_scanner")
    assert skip("/System/Library/x") is True
    assert skip("/SYSTEM/Library/x") is True, "case-variant must still be skipped"
    assert skip("/System/library/X.DYLIB") is True


def test_darwin_relative_fragment_entries_match_anywhere_in_path():
    """Regression: 32 of 58 mac_skip_directory entries have no leading '/' (e.g.
    "node_modules/", "Library/Application Support/Slack/"), but the matcher did
    normalized_path.startswith(entry) - a relative string can never be a prefix of an
    absolute path, so these entries matched nothing, ever. They must match as a fragment
    anywhere in the path instead, the same semantics skip_path_fragments already uses.
    """
    cfg, skip = _predicate("Darwin", "/usr/local/yara_scanner")
    assert skip("/Users/bob/project/node_modules/pkg/evil.js") is True
    assert skip("/Users/bob/Library/Application Support/Slack/storage/x") is True
    assert skip("/Users/bob/dev/PycharmProjects/proj/.idea/x") is True
    assert skip("/Users/bob/proj/build/out.o") is True


def test_darwin_relative_fragment_has_component_boundaries():
    """The fragment check must not match a bare substring occurrence mid-name."""
    cfg, skip = _predicate("Darwin", "/usr/local/yara_scanner")
    assert skip("/Users/bob/notnode_modules/x") is False
    assert skip("/Users/bob/mybuild/x") is False


def test_darwin_anchor_entries_stay_root_scoped_not_anywhere():
    """Absolute entries like '/System/' must remain anchored at the real filesystem root -
    they must NOT become 'anywhere' fragments, or a user directory that happens to share
    the name (e.g. "~/System/") would be wrongly skipped.
    """
    cfg, skip = _predicate("Darwin", "/usr/local/yara_scanner")
    assert skip("/Users/bob/System/notes.txt") is False


def test_darwin_scanner_dir_bare_root_is_skipped():
    cfg, skip = _predicate("Darwin", "/usr/local/yara_scanner")
    assert skip("/usr/local/yara_scanner") is True


def test_darwin_case_variant_scan_target_no_longer_defeats_skip():
    """Reproduces the audit's exact live finding: a scan target typed in different case
    than YARA_SCANNER_DIR previously bypassed the skip for every path under it, because
    os.walk preserves the caller-supplied casing of the argument itself.
    """
    cfg, skip = _predicate("Darwin", "/usr/local/YARA_SCANNER")
    assert skip("/usr/local/yara_scanner/evidence/e.zip") is True
    assert skip("/usr/local/YARA_SCANNER/evidence/e.zip") is True


# ------------------------------------------------------------------ hygiene
def test_building_configs_creates_no_directories():
    """These tests must never write to the filesystem.

    ScanConfig eagerly creates its working tree, and the foreign-platform scanner_dir
    values used above are legal directory NAMES on a POSIX host — "C:\\yara_scanner" is one
    directory whose name contains backslashes, not a drive reference. Before os.makedirs
    was stubbed, running this file created 37 junk directories in the repo root, and
    .gitignore's *.log rule plus git's not tracking empty dirs kept `git status` clean, so
    nothing surfaced it. This asserts the stub is actually in effect rather than trusting it.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    before = set(os.listdir(repo_root))

    for plat, sdir in (("Windows", "C:\\yara_scanner"),
                       ("Linux", "/opt/yara_scanner"),
                       ("Darwin", "/usr/local/yara_scanner")):
        _predicate(plat, sdir)

    new = set(os.listdir(repo_root)) - before
    assert not new, f"tests polluted the repo root with: {sorted(new)}"
    assert not [e for e in os.listdir(repo_root) if "\\" in e], \
        "a backslash-named directory was created in the repo root"


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))
