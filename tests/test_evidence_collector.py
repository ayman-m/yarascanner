#!/usr/bin/env python3
"""Unit tests for EvidenceCollector ZIP packaging — pure, no network, no agent.

Two behaviours are pinned here.

Whether matched files are copied at all is governed by COLLECT_MATCHED_FILES, which
defaults OFF so a scan does not write gigabytes to the host it is scanning. Metadata
(paths + SHA256 + alert texts) is packaged either way.

When copying IS enabled the archive is content-addressed: each file is stored as
`matched_files/<sha256>`, so identical content collapses to a single blob while
file_mapping.txt keeps the full path -> hash relation that makes that lossless.
"""
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from xsiam_yara_scanner import EvidenceCollector  # noqa: E402


class FakeConfig:
    """Minimal stand-in for ScanConfig — only the fields EvidenceCollector touches.

    Defaults to collect_matched_files=True because most tests here exercise the
    packaging path; the default-off behaviour is asserted explicitly instead.
    """

    def __init__(self, tmpdir, collect_matched_files=True):
        self.hostname = "testhost"
        self.os_info = "TestOS [x86_64]"
        self.ip_addresses = ["10.0.0.1"]
        self.alert_dir = os.path.join(tmpdir, "alert")
        self.evidence_zip = os.path.join(tmpdir, "evidence.zip")
        self.file_mapping = os.path.join(tmpdir, "file_mapping.txt")
        self.collect_matched_files = collect_matched_files
        os.makedirs(self.alert_dir, exist_ok=True)


def _make_corpus(tmpdir, layout):
    """Write files described by {relpath: content} and return their absolute paths."""
    paths = []
    for rel, content in layout.items():
        full = os.path.join(tmpdir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content)
        paths.append(full)
    return paths


def test_duplicate_content_stored_once(tmp_path):
    """Identical content at three paths must produce exactly one ZIP blob.

    Regression: entries were named by hash but iterated by path, so N copies of the
    same bytes were each written under the same arcname. zipfile permits that - it
    only warns - so the archive silently carried N copies of every duplicated file.
    On a Windows System32 scan that inflated the archive to gigabytes.
    """
    tmpdir = str(tmp_path)
    payload = b"MZ\x90\x00" + b"duplicated dll body" * 100
    paths = _make_corpus(tmpdir, {
        "System32/a.dll": payload,
        "System32/downlevel/a.dll": payload,
        "SysWOW64/a.dll": payload,
    })

    collector = EvidenceCollector(FakeConfig(tmpdir))
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with zipfile.ZipFile(collector.config.evidence_zip) as zf:
        blobs = [n for n in zf.namelist() if n.startswith("matched_files/")]

    assert len(blobs) == 1, f"expected 1 deduped blob, got {len(blobs)}: {blobs}"
    assert len(set(blobs)) == len(blobs), "duplicate arcnames in archive"


def test_distinct_content_each_stored(tmp_path):
    """Dedupe must key on content, not filename — different bytes all survive."""
    tmpdir = str(tmp_path)
    paths = _make_corpus(tmpdir, {
        "one/same_name.bin": b"alpha payload",
        "two/same_name.bin": b"beta payload",
        "three/same_name.bin": b"gamma payload",
    })

    collector = EvidenceCollector(FakeConfig(tmpdir))
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with zipfile.ZipFile(collector.config.evidence_zip) as zf:
        blobs = [n for n in zf.namelist() if n.startswith("matched_files/")]

    assert len(blobs) == 3, f"expected 3 distinct blobs, got {blobs}"


def test_mapping_still_lists_every_duplicate_path(tmp_path):
    """Deduping the payload must not cost traceability.

    file_mapping.txt is the index that makes dedupe lossless: it maps every original
    path to its hash, so an analyst can still see all three locations even though the
    bytes are stored once.
    """
    tmpdir = str(tmp_path)
    payload = b"repeated content"
    paths = _make_corpus(tmpdir, {
        "System32/a.dll": payload,
        "SysWOW64/a.dll": payload,
    })

    collector = EvidenceCollector(FakeConfig(tmpdir))
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with open(collector.config.file_mapping, encoding="utf-8") as fh:
        mapping = fh.read()

    for p in paths:
        assert p in mapping, f"{p} missing from file_mapping.txt"


def test_missing_file_does_not_abort_packaging(tmp_path):
    """A file deleted between match and packaging must not lose the rest of the ZIP."""
    tmpdir = str(tmp_path)
    paths = _make_corpus(tmpdir, {
        "keep.bin": b"still here",
        "vanish.bin": b"about to disappear",
    })
    os.remove(paths[1])

    collector = EvidenceCollector(FakeConfig(tmpdir))
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with zipfile.ZipFile(collector.config.evidence_zip) as zf:
        blobs = [n for n in zf.namelist() if n.startswith("matched_files/")]

    assert len(blobs) == 1, f"surviving file should still be packaged, got {blobs}"


def test_metadata_only_when_collection_disabled(tmp_path):
    """With collection off, no file bytes are copied — but evidence is still usable.

    This is the default. The archive must still carry file_mapping.txt and the alert
    texts, which is what lets a responder locate and pull any matched file on demand
    rather than having it pre-copied onto the host's own disk.
    """
    tmpdir = str(tmp_path)
    paths = _make_corpus(tmpdir, {"System32/big.dll": b"x" * 50000})

    cfg = FakeConfig(tmpdir, collect_matched_files=False)
    with open(os.path.join(cfg.alert_dir, "SomeRule.txt"), "w", encoding="utf-8") as fh:
        fh.write("offset 0x100\n")

    collector = EvidenceCollector(cfg)
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with zipfile.ZipFile(cfg.evidence_zip) as zf:
        names = zf.namelist()

    assert not [n for n in names if n.startswith("matched_files/")], \
        f"no file bytes should be copied when disabled, got {names}"
    assert "file_mapping.txt" in names, "mapping must survive so files remain locatable"
    assert "alerts/SomeRule.txt" in names, "alert texts must survive"

    with open(cfg.file_mapping, encoding="utf-8") as fh:
        assert paths[0] in fh.read(), "path must still be recorded when copying is off"


def test_collection_disabled_keeps_archive_small(tmp_path):
    """The point of the default: archive size must not track matched-file size."""
    tmpdir = str(tmp_path)
    paths = _make_corpus(tmpdir, {f"f{i}.bin": os.urandom(200000) for i in range(5)})

    cfg = FakeConfig(tmpdir, collect_matched_files=False)
    collector = EvidenceCollector(cfg)
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    corpus_bytes = sum(os.path.getsize(p) for p in paths)
    zip_bytes = os.path.getsize(cfg.evidence_zip)
    assert zip_bytes < corpus_bytes / 10, (
        f"archive {zip_bytes}B should be a small fraction of {corpus_bytes}B of matches"
    )


if __name__ == "__main__":
    import subprocess
    raise SystemExit(subprocess.call([sys.executable, "-m", "pytest", __file__, "-v"]))


# ------------------------------------------------------------------ XDR parity
def test_xdr_duplicate_content_stored_once(tmp_path):
    """Evidence packaging is a SHARED concern: both editions content-address the archive
    as matched_files/<sha256> but iterated by PATH, so identical bytes at several paths
    each wrote a full copy under one entry name. XDR gates copying behind collect_files
    (default off), so this only bites a deployer who opts in - but the defect is identical.
    """
    import xdr_yara_scanner as xm

    tmpdir = str(tmp_path)
    payload = b"MZ\x90\x00" + b"duplicated dll body" * 100
    paths = _make_corpus(tmpdir, {
        "System32/a.dll": payload,
        "System32/downlevel/a.dll": payload,
        "SysWOW64/a.dll": payload,
    })

    cfg = FakeConfig(tmpdir)
    cfg.collect_files = True          # XDR's toggle name; off by default
    collector = xm.EvidenceCollector(cfg)
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with zipfile.ZipFile(cfg.evidence_zip) as zf:
        blobs = [n for n in zf.namelist() if n.startswith("matched_files/")]

    assert len(blobs) == 1, f"expected 1 deduped blob, got {len(blobs)}"
    assert len(set(blobs)) == len(blobs), "duplicate arcnames in archive"


def test_xdr_metadata_only_by_default(tmp_path):
    """collect_files defaults off there, so the archive must carry no file bytes."""
    import xdr_yara_scanner as xm

    tmpdir = str(tmp_path)
    paths = _make_corpus(tmpdir, {"big.dll": b"x" * 50000})
    cfg = FakeConfig(tmpdir)
    cfg.collect_files = False
    collector = xm.EvidenceCollector(cfg)
    for p in paths:
        collector.add_matched_file(p)
    collector.collect_evidence()

    with zipfile.ZipFile(cfg.evidence_zip) as zf:
        names = zf.namelist()
    assert not [n for n in names if n.startswith("matched_files/")]
    assert "file_mapping.txt" in names, "mapping must survive so files remain locatable"
