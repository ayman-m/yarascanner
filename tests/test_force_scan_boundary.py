#!/usr/bin/env python3
"""The force-scan allowlist must never walk off this host — in BOTH editions.

`force_scan_fragments` is an allowlist that overrides path-based skips so browser caches
and profiles get scanned even though a broader rule excludes their parent. That is correct
for local disk and wrong for anything mounted: a Time Machine volume under /Volumes/ holds
one browser cache per backup snapshot, so an unguarded fragment drags the walker across
every snapshot on the disk.

XSIAM guards this with `force_scan_never_under`, consulted before the allowlist. XDR had
the allowlist and no guard at all, so its force-scan overrides had no backstop.

XDR was also missing the trailing-separator probe: os.walk yields a directory root with no
trailing separator, so ".../Library/Caches/Firefox" failed to match the
"/library/caches/firefox/" fragment while still matching the broad "/library/caches/" skip.
The directory was pruned wholesale and no file inside ever reached the allowlist — the
allowlist silently did nothing for exactly the paths it was written for.

Both editions are pinned here because both carry independent copies of this predicate.
"""
import base64
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]
RULE_B64 = base64.b64encode(b'rule t { strings: $a = "AAAA" condition: $a }').decode()


def _predicate(edition):
    """Real ScanConfig + bound predicate, on a Darwin branch, touching no filesystem."""
    import importlib
    mod = importlib.import_module(edition)
    with mock.patch("platform.system", return_value="Darwin"), mock.patch("os.makedirs"):
        cfg = mod.ScanConfig(RULE_B64, scan_folder="/tmp")
        holder = type("H", (), {})()
        holder.config = cfg
        holder.scan_active = True

        def check(path):
            with mock.patch("platform.system", return_value="Darwin"):
                return mod.YaraScanner._is_special_file(holder, path)
        return check


@pytest.mark.parametrize("edition", EDITIONS)
def test_force_scan_wins_on_local_disk(edition):
    """The allowlist must still do its job where it is safe to."""
    assert _predicate(edition)("/Users/x/Library/Caches/Firefox/cache2/entries/abc") is False, (
        f"{edition}: the browser-cache allowlist stopped working on local disk")


@pytest.mark.parametrize("edition", EDITIONS)
def test_bare_directory_root_reaches_the_allowlist(edition):
    """os.walk yields roots without a trailing separator; the probe must append one."""
    assert _predicate(edition)("/Users/x/Library/Caches/Firefox") is False, (
        f"{edition}: the bare directory root was pruned, so nothing inside it could ever "
        f"be reached by the allowlist")


@pytest.mark.parametrize("edition", EDITIONS)
@pytest.mark.parametrize("mount", ["/Volumes/TimeMachine", "/media/usb", "/mnt/backup", "/net/share"])
def test_boundary_skips_veto_the_allowlist(edition, mount):
    """A mounted volume is off-host. No allowlist fragment may override that."""
    path = f"{mount}/Users/x/Library/Caches/Firefox/cache2/entries/abc"
    assert _predicate(edition)(path) is True, (
        f"{edition}: force-scan walked onto {mount} — the allowlist has no boundary guard, "
        f"so a Time Machine disk would be scanned once per backup snapshot")


@pytest.mark.parametrize("edition", EDITIONS)
def test_both_editions_define_the_guard(edition):
    """Parity: the guard list itself must exist, not just happen to be unreachable."""
    import importlib
    mod = importlib.import_module(edition)
    with mock.patch("platform.system", return_value="Darwin"), mock.patch("os.makedirs"):
        cfg = mod.ScanConfig(RULE_B64, scan_folder="/tmp")
    guard = getattr(cfg, "force_scan_never_under", ())
    assert guard, f"{edition}: force_scan_never_under is missing or empty"
    for expected in ("/volumes/", "/media/", "/mnt/", "/net/"):
        assert expected in guard, f"{edition}: {expected} missing from force_scan_never_under"
