#!/usr/bin/env python3
"""skip_reasons keys must be bounded — they are aggregate labels, not per-file detail.

scan_file()'s catch-all returned str(exception) and _worker used that string directly as
a skip_reasons dict KEY. Both common error texts embed the absolute path:

    yara.Error  -> 'could not open file "C:\\...\\thing.dll"'
    OSError     -> '[Errno 2] No such file or directory: /path/to/thing'

so the dict grew one unique key per errored file, unbounded. On a full-system scan, files
vanishing or locking between the access check and rules.match is routine. The whole dict
then ships in the final report and a statistics event — measured at 307,780 bytes for
5,000 errored files, all of it path noise the per-file error log already carries.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


def _mod(name):
    import importlib
    return importlib.import_module(name)


@pytest.mark.parametrize("edition", EDITIONS)
def test_reason_never_embeds_the_path(edition):
    """The two real error shapes must both reduce to a path-free label."""
    m = _mod(edition)
    cases = [
        OSError(2, "No such file or directory", "/very/unique/path/to/thing.bin"),
        Exception('could not open file "C:\\Windows\\System32\\unique_thing.dll"'),
    ]
    for exc in cases:
        reason = m._scan_error_reason(exc)
        assert "unique" not in reason.lower(), f"path leaked into the key: {reason!r}"
        assert len(reason) < 60, f"key is unbounded in length: {reason!r}"


@pytest.mark.parametrize("edition", EDITIONS)
def test_many_distinct_paths_collapse_to_few_keys(edition):
    """1,000 errored files must not produce 1,000 dict keys."""
    m = _mod(edition)
    keys = {m._scan_error_reason(OSError(2, "No such file or directory", f"/p/{i}.bin"))
            for i in range(1000)}
    assert len(keys) == 1, f"expected 1 aggregate key, got {len(keys)}: {sorted(keys)[:5]}"


@pytest.mark.parametrize("edition", EDITIONS)
def test_error_type_is_still_distinguishable(edition):
    """Bounding must not flatten genuinely different failures into one bucket."""
    m = _mod(edition)
    a = m._scan_error_reason(OSError(2, "No such file", "/x"))
    b = m._scan_error_reason(MemoryError("out of memory"))
    assert a != b, "different exception types must remain distinguishable"


@pytest.mark.parametrize("edition", EDITIONS)
def test_reason_still_matches_the_scan_errors_filter(edition):
    """The final report counts error reasons by looking for 'error' in the key.

    If the bounded label stopped containing that substring, scan_errors would silently
    drop to zero and a scan full of unreadable files would report none.
    """
    m = _mod(edition)
    assert "error" in m._scan_error_reason(OSError(2, "nope", "/x")).lower()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
