#!/usr/bin/env python3
"""Two Round 3 defects in the failed-rule diagnostics, both found on a live crafted pack.

DEFECT 1 — the "<-- ERROR HERE" marker pointed at the wrong rule.

The compile site builds `preamble + "\n\n" + rule_content` and hands THAT to libyara, so
libyara's "line N" counts from the preamble's first line. The echo enumerates rule_content
from 1. With a 4-import preamble the marker landed 6 lines too far down: on the ground-truth
leg both failed rules had it past their own closing brace, on a comment belonging to the
NEXT rule. An operator following the marker reads the wrong rule entirely.

The criterion's own setup called for a no-import pack, which is exactly why this hid: real
packs carry imports.

DEFECT 2 — dumps were overwritten across runs.

Filenames were failed_rule_<rule>.yar and skipped_rule_<rule>_<module>.yar, with no run_id,
while failed_rules/ is deliberately never pruned. Measured live: 8 dumps from three runs,
4 of them rewritten by the newest run. Leg G reported skipped_rules=3 with only 2 dumps
still bearing its timestamp; leg A reported 4 failures against 2 survivors. Triaging an
older pack after a newer scan shows the newer run's contents under the older run's names,
which is worse than having no dump at all.
"""
import importlib
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


class _Logger:
    """Captures what the error logger would have written."""
    def __init__(self):
        self.lines = []

    def error(self, msg):
        self.lines.append(str(msg))


def _error_logger(mod, edition):
    el = object.__new__(mod.ErrorLogger)
    el.error_logger = _Logger()
    el.has_errors = False
    el.failed_rules_count = 0
    el.config = type("_C", (), {"run_id": "20260819_120000_000001"})()
    return el


BODY = "\n".join([
    "rule broken_one",          # body line 1
    "{",                        # 2
    "    strings:",             # 3
    '        $x = "unterminated',  # 4  <- the real error
    "    condition:",           # 5
    "        $x",               # 6
    "}",                        # 7
])
PREAMBLE_LINES = 6              # 4 imports + the two blank lines the compile site adds


@pytest.mark.parametrize("edition", EDITIONS)
def test_marker_is_offset_by_the_preamble(edition):
    m = importlib.import_module(edition)
    el = _error_logger(m, edition)
    # libyara counted the preamble: body line 4 is line 10 of what it compiled
    el.log_rule_compilation_error("broken_one", BODY,
                                  Exception("line 10: unterminated string"),
                                  preamble_lines=PREAMBLE_LINES)
    marked = [l for l in el.error_logger.lines if "ERROR HERE" in l]
    assert len(marked) == 1, f"expected exactly one marker, got {len(marked)}"
    n = int(re.match(r"\s*(\d+):", marked[0]).group(1))
    assert n == 4, (
        f"marker on body line {n}, expected 4. Without the preamble offset it lands on "
        f"line 10 — past the rule's closing brace at line 7, i.e. on the next rule.")
    assert "unterminated" in marked[0]


@pytest.mark.parametrize("edition", EDITIONS)
def test_an_error_inside_the_preamble_marks_nothing(edition):
    """Better to mark nothing than to mark an innocent body line."""
    m = importlib.import_module(edition)
    el = _error_logger(m, edition)
    el.log_rule_compilation_error("broken_one", BODY,
                                  Exception("line 2: bad import"),
                                  preamble_lines=PREAMBLE_LINES)
    marked = [l for l in el.error_logger.lines if "ERROR HERE" in l]
    assert not marked, (
        f"the error is in the shared preamble (line 2 of 6), but a body line was marked: "
        f"{marked}")


@pytest.mark.parametrize("edition", EDITIONS)
def test_no_preamble_still_marks_correctly(edition):
    m = importlib.import_module(edition)
    el = _error_logger(m, edition)
    el.log_rule_compilation_error("broken_one", BODY,
                                  Exception("line 4: unterminated string"),
                                  preamble_lines=0)
    marked = [l for l in el.error_logger.lines if "ERROR HERE" in l]
    assert len(marked) == 1 and marked[0].strip().startswith("4:")


@pytest.mark.parametrize("edition", EDITIONS)
def test_dump_filenames_carry_the_run_id(edition):
    """Without run_id in the name, a later scan overwrites an earlier scan's evidence."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        edition.split("_")[0], edition + ".py")
    src = open(path, encoding="utf-8").read()
    for pattern in ('f"failed_rule_{display_name}',
                    'f"skipped_rule_{display_name}_{missing_module}',
                    'f"skipped_rule_{display_name}_{_missing}'):
        i = src.find(pattern)
        assert i != -1, f"{pattern} not found in {edition}"
        line = src[i:src.index("\n", i)]
        assert "run_id" in line, (
            f"dump filename has no run_id, so a later run overwrites it: {line.strip()}")
