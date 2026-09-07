#!/usr/bin/env python3
"""The War Room renderer's generic half must be one function, however many copies of it ship.

An automation is delivered as a single yml and the tenant resolves no cross-script imports, so
a shared helper exists as N inlined copies. This repo's answer to that is not trust, it is a
byte-for-byte gate - and it exists because the pack has already shipped the same function two
different ways: the fast path's `_READ_LIMIT` truncation guard was present in the `.py` and
absent from the deliverable that actually ran, with a green suite throughout.

These four are the generic half of the markdown renderer - `_n`, `_md_table`, `_md_capped` and
`_MD_ROW_CAP`. The per-automation half (the record constructors, and each automation's own
`render_*_markdown`) is deliberately NOT gated: they report different things, and forcing them
identical would be forcing the automations to be identical.

Two of these carry a correctness rule rather than a formatting preference, which is why a
drifted copy is worse than an ugly one:

  * `_md_table` ESCAPES PIPES. Rule names arrive from a YARA ruleset and hostnames from an
    endpoint. One unescaped `|` in either shears a column off every row below it, and markdown
    does not error - the operator reads a table that is quietly wrong. A copy that lost the
    escape would look fine in every test that does not happen to use a pipe.
  * `_md_capped` NAMES THE CONTEXT KEY holding the untruncated list. A copy that dropped that
    line would truncate silently, which reads as "that was everything".

GATING IS BY DISCOVERY, NOT BY LIST - the same choice the lock gate makes. If a file carries
one of these names it is compared, so a tenth automation added tomorrow is covered the day it
is written rather than the day someone remembers to add it here.
"""
import ast
import io
import os

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts")
_CANONICAL = os.path.join(_SCRIPTS, "YaraConsolidateSummary", "YaraConsolidateSummary.py")

FUNCS = ("_n", "_md_table", "_md_capped")
CONSTS = ("_MD_ROW_CAP",)
NAMES = FUNCS + CONSTS


def _index(path):
    """{name: source text} for the gated names defined at module level in `path`."""
    text = io.open(path, encoding="utf-8").read()
    lines = text.splitlines(keepends=True)
    out = {}
    for node in ast.parse(text).body:
        name = None
        if isinstance(node, ast.FunctionDef) and node.name in FUNCS:
            name = node.name
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in CONSTS):
            name = node.targets[0].id
        if name:
            out[name] = "".join(lines[node.lineno - 1:node.end_lineno])
    return out


def _automations():
    return sorted(d for d in os.listdir(_SCRIPTS)
                  if os.path.isfile(os.path.join(_SCRIPTS, d, d + ".py")))


def _carriers():
    """Every automation that carries at least one of the gated names. Discovered, not listed."""
    out = {}
    for name in _automations():
        idx = _index(os.path.join(_SCRIPTS, name, name + ".py"))
        if idx:
            out[name] = idx
    return out


def test_the_canonical_copy_defines_all_of_them():
    """Guards the gate itself: if the canonical file loses one, every comparison below would
    silently pass by comparing nothing."""
    missing = sorted(set(NAMES) - set(_index(_CANONICAL)))
    assert not missing, "test is stale - not in %s: %s" % (_CANONICAL, missing)


@pytest.mark.parametrize("automation", sorted(_carriers()))
def test_the_markdown_helpers_are_byte_identical(automation):
    canonical = _index(_CANONICAL)
    mine = _carriers()[automation]
    for name in sorted(mine):
        assert mine[name] == canonical[name], (
            "%s has drifted in %s.\n--- canonical (YaraConsolidateSummary)\n%s\n--- %s\n%s"
            % (name, automation, canonical[name], automation, mine[name]))


@pytest.mark.parametrize("automation", sorted(_carriers()))
def test_a_carrier_carries_the_whole_set(automation):
    """A partial copy is the one state the propagator cannot repair safely: it cannot tell a
    file that never had `_md_capped` from one whose copy was deleted on purpose. `_md_capped`
    calls `_md_table` calls `_n`, so a file with the last but not the first raises NameError
    on the line that was supposed to keep a 200-row table out of the War Room."""
    missing = sorted(set(NAMES) - set(_carriers()[automation]))
    assert not missing, (
        "%s carries part of the markdown helper set but is missing %s - run the propagator"
        % (automation, missing))


def test_the_pipe_escape_survives_in_every_copy():
    """The rule that makes a drifted copy dangerous rather than merely inconsistent, asserted
    on behaviour rather than on source text - a copy could keep the characters and lose the
    call."""
    for automation, idx in sorted(_carriers().items()):
        ns = {}
        exec(idx["_n"] + "\n" + idx["_md_table"], ns)          # noqa: S102 - gate fixture
        row = ns["_md_table"](["a", "b"], [("we|ird", "fine")])
        assert "we\\|ird" in row, "%s: _md_table stopped escaping pipes" % automation
        assert len(row.splitlines()) == 3, (
            "%s: an unescaped pipe split the row into %d lines"
            % (automation, len(row.splitlines())))
