#!/usr/bin/env python3
"""_iter_hit_fields accepts exactly one shape: a live yara Match object.

It previously also accepted a serialised dict, implying a match cache the scanner does
not have. That arm was unreachable — every call site iterates `matches`, which has one
binding to `self.rules.match(...)` — and unsafe: its decode fallback was
`hx.encode("utf-8", errors="ignore")` on anything `bytes.fromhex` rejected, so a non-hex
string yielded wrong bytes silently rather than raising.

These tests pin the surviving contract, so the deletion cannot quietly change what the
live path produces.

Both editions are covered. XDR reached the same dead end by a different route, so its
unreachability was re-enumerated rather than assumed:

  * four call sites (the rules_matched comprehension, the _write_alerts loop, the
    total_string_matches sum, and rules_triggered) all iterate `matches`;
  * `matches` has one binding, `matches = self.rules.match(...)`;
  * _write_alerts takes `matches` as a parameter but has a single caller, passing that
    same local;
  * nothing outside the file imports _iter_hit_fields.

XDR differed in one way that mattered: it DID contain a producer of the dict shape,
_serialize_matches(), which XSIAM never had. That producer had zero call sites of its
own, so it was dead code feeding a dead branch. Both were removed together -- deleting
the consumer alone would leave a live-looking helper whose output nothing could accept.
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EDITIONS = ["xsiam_yara_scanner", "xdr_yara_scanner"]


@pytest.fixture(params=EDITIONS)
def mod(request):
    m = importlib.reload(importlib.import_module(request.param))
    yield m
    importlib.reload(importlib.import_module(request.param))


class _Instance:
    def __init__(self, offset, data):
        self.offset = offset
        self.matched_data = data


class _StringMatch:
    """yara-python >= 4.3 shape: identifier plus instances."""
    def __init__(self, identifier, instances):
        self.identifier = identifier
        self.instances = instances


class _Match:
    def __init__(self, rule, tags, meta, strings):
        self.rule = rule
        self.tags = tags
        self.meta = meta
        self.strings = strings


def test_modern_match_object(mod):
    hit = _Match("r1", ["t"], {"author": "x"},
                 [_StringMatch("$a", [_Instance(0, b"AB"), _Instance(7, b"CD")])])
    rule, tags, meta, strings = mod._iter_hit_fields(hit)
    assert rule == "r1" and tags == ["t"] and meta == {"author": "x"}
    assert strings == [(0, "$a", b"AB"), (7, "$a", b"CD")]


def test_legacy_tuple_strings(mod):
    """yara-python < 4.3 returned (offset, id, data) triples — still supported."""
    hit = _Match("r2", [], {}, [(3, "$b", b"XY")])
    rule, _, _, strings = mod._iter_hit_fields(hit)
    assert rule == "r2" and strings == [(3, "$b", b"XY")]


def test_a_match_with_no_strings(mod):
    """Condition-only rules produce no string instances."""
    hit = _Match("cond_only", [], {}, [])
    rule, tags, meta, strings = mod._iter_hit_fields(hit)
    assert rule == "cond_only" and strings == []


def test_dict_input_is_no_longer_silently_accepted(mod):
    """A dict must now fail loudly rather than be decoded into wrong bytes.

    The removed arm's fallback turned a non-hex string into utf-8 bytes without
    complaint, so corrupt offsets and matched data would have flowed downstream looking
    entirely normal.
    """
    with pytest.raises(AttributeError):
        mod._iter_hit_fields({"rule": "r", "strings": [(0, "$a", "zznothex")]})


def test_the_dict_producer_is_gone(mod):
    """_serialize_matches was the only thing that could build the dict shape.

    XDR carried it with zero call sites; XSIAM never had it. Keeping a producer for a
    shape the consumer no longer accepts is a trap: the next caller gets an
    AttributeError from a helper that looks supported.
    """
    assert not hasattr(mod, "_serialize_matches"), (
        "a serialiser for the removed dict shape is still exported")
