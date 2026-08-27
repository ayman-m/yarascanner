#!/usr/bin/env python3
"""YaraRulesDecode: the scanner's yarafile base64 back into readable rules.

The encode step alone is unfalsifiable - it emits a blob nobody can read, so a bug in it
produces a wave that silently scans for the wrong thing. Decoding is what makes the encode
checkable, and the corpus below is the real assertion: every rule STRUCTURE a customer might
upload has to survive the round trip, not just the tidy one-rule sample the encoder was
written against.

Two of these structures were rejected outright by the first encoder, and this corpus is how
that was found:
  - a regex literal containing a brace (/a\\{b/) counted as a structural brace and failed the
    balance check
  - a UTF-8 BOM - what Notepad writes by default - sat in front of the first `rule`, so the
    file read as containing no rules at all
Both were valid rulesets refused with a confident, wrong error. That is the failure mode this
file exists to prevent.
"""
import ast
import base64
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import _install_xsoar_stubs  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts")
_ENCODE_PY = os.path.join(_SCRIPTS, "YaraRulesFromFile", "YaraRulesFromFile.py")
_DECODE_PY = os.path.join(_SCRIPTS, "YaraRulesDecode", "YaraRulesDecode.py")


def _load(path, name):
    _install_xsoar_stubs()
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def enc():
    return _load(_ENCODE_PY, "yara_rules_from_file_rt")


@pytest.fixture(scope="module")
def dec():
    return _load(_DECODE_PY, "yara_rules_decode")


# Every one of these is a legal ruleset a customer could plausibly upload. Keyed by the
# structural feature it exercises, so a failure names the feature rather than an index.
CORPUS = {
    "plain": 'rule Plain {\n  condition:\n    true\n}\n',
    "tags": 'rule Tagged : malware trojan {\n  condition:\n    true\n}\n',
    "import_module": 'import "pe"\n\nrule UsesPe {\n  condition:\n    pe.is_pe\n}\n',
    "private_global": 'global private rule Hidden {\n  condition:\n    true\n}\n',
    "meta_block": ('rule WithMeta {\n  meta:\n    author = "soc"\n    ref = "CVE-2026-1"\n'
                   '  condition:\n    true\n}\n'),
    "hex_string_jump": ('rule HexJump {\n  strings:\n    $h = { 4D 5A [0-4] 90 90 }\n'
                        '  condition:\n    $h\n}\n'),
    "regex_quantifier": ('rule ReQuant {\n  strings:\n    $r = /ab{2,3}c/ nocase\n'
                         '  condition:\n    $r\n}\n'),
    "regex_escaped_brace": ('rule ReBrace {\n  strings:\n    $r = /a\\{b/\n'
                            '  condition:\n    $r\n}\n'),
    "brace_inside_string": ('rule StrBrace {\n  strings:\n    $s = "}"\n'
                            '  condition:\n    $s\n}\n'),
    "block_comment_brace": 'rule CmtBrace {\n  /* } not a close */\n  condition:\n    true\n}\n',
    "line_comment_brace": 'rule LineCmt {\n  // } not a close\n  condition:\n    true\n}\n',
    "crlf_line_endings": 'rule Crlf {\r\n  condition:\r\n    true\r\n}\r\n',
    "unicode_metadata": ('rule Uni {\n  meta:\n    a = "café ünïcode"\n'
                         '  condition:\n    true\n}\n'),
    "nested_condition": ('rule Nested {\n  condition:\n    (1 of them) and '
                         '(for any i in (0..10) : (i == 1))\n}\n'),
    "many_rules": "".join('rule R%d {\n  condition:\n    true\n}\n\n' % i for i in range(25)),
    "string_modifiers": ('rule Mods {\n  strings:\n    $a = "x" wide ascii nocase\n'
                         '  condition:\n    $a\n}\n'),
}


@pytest.mark.parametrize("label", sorted(CORPUS))
def test_every_rule_structure_survives_the_round_trip(label, enc, dec):
    """encode -> decode must return the same rules and agree on the hash, for every shape."""
    text = CORPUS[label]
    e = enc.validate_rules(text)
    assert e["valid"], "%s was REJECTED by the encoder: %s" % (label, e["errors"])
    d = dec.decode_rules(e["b64"], expected_hash=e["rule_hash"])
    assert d["ok"], "%s decoded but failed validation: %s" % (label, d["errors"])
    assert d["rules"] == text, "%s did not survive the round trip byte-for-byte" % label
    assert d["rule_hash"] == e["rule_hash"], label
    assert d["hash_matches"] is True, label
    assert d["rule_names"] == e["rule_names"], label


def test_a_utf8_bom_round_trips_to_the_NORMALISED_text_not_the_original(enc, dec):
    """The one structure where the round trip is deliberately not byte-exact.

    Notepad writes a BOM by default. The encoder strips it - libyara would not accept it
    either - which means the hash, the dispatched bytes and this output all agree with each
    other and all differ from the uploaded file by that BOM. Asserting it here so the
    contract is pinned rather than discovered later by someone diffing a file against its
    own decoded copy.
    """
    original = "﻿rule Bom {\n  condition:\n    true\n}\n"
    e = enc.validate_rules(original)
    assert e["valid"], e["errors"]
    d = dec.decode_rules(e["b64"], expected_hash=e["rule_hash"])
    assert d["ok"]
    assert d["rules"] == original.lstrip("﻿")
    assert d["rules"] != original, "the BOM should have been normalised away"
    assert d["hash_matches"] is True


def test_corrupted_base64_is_refused_rather_than_decoded_to_garbage(dec):
    """The property the whole automation rests on.

    base64.b64decode DISCARDS characters outside the alphabet unless validate=True. Without
    that flag a payload mangled in transit decodes to something plausible-looking, and an
    automation whose job is to be evidence would quietly launder the corruption.
    """
    good = base64.b64encode(b"rule R {\n  condition:\n    true\n}\n").decode()
    corrupt = good[:8] + "!!*(" + good[8:]
    d = dec.decode_rules(corrupt)
    assert d["ok"] is False
    assert any("base64" in e.lower() for e in d["errors"]), d["errors"]


def test_urlsafe_base64_is_named_rather_than_failing_obscurely(dec):
    payload = b"rule R {\n  condition:\n    true\n}\n" + b"\xfb\xff\xfe"
    d = dec.decode_rules(base64.urlsafe_b64encode(payload).decode())
    assert d["ok"] is False
    assert any("url-safe" in e.lower() for e in d["errors"]), d["errors"]


def test_whitespace_and_line_wrapping_are_repaired(enc, dec):
    """A payload copied out of a report or a context dump arrives wrapped. That is layout
    damage, not corruption, and refusing it would send an operator hunting for a bug that
    is not there."""
    e = enc.validate_rules(CORPUS["many_rules"])
    wrapped = "\n".join(e["b64"][i:i + 64] for i in range(0, len(e["b64"]), 64))
    d = dec.decode_rules("  " + wrapped + "  \n")
    assert d["ok"], d["errors"]
    assert d["rule_hash"] == e["rule_hash"]


def test_missing_padding_is_repaired(enc, dec):
    e = enc.validate_rules(CORPUS["plain"])
    assert e["b64"].endswith("="), "pick a sample whose encoding actually carries padding"
    d = dec.decode_rules(e["b64"].rstrip("="))
    assert d["ok"], d["errors"]
    assert d["rule_hash"] == e["rule_hash"]


def test_a_hash_mismatch_is_reported_without_claiming_the_rules_are_invalid(enc, dec):
    """Two different findings that must not be conflated: 'this is not valid YARA' and 'this
    is valid YARA, but not the ruleset you were told'. Folding the second into `ok` would
    have an operator debugging the rules when the real problem is provenance."""
    e = enc.validate_rules(CORPUS["plain"])
    d = dec.decode_rules(e["b64"], expected_hash="deadbeefcafe")
    assert d["ok"] is True, "valid rules must stay valid when the hash comparison fails"
    assert d["hash_matches"] is False
    assert d["rule_hash"] == e["rule_hash"]


def test_no_expected_hash_leaves_the_comparison_unset_not_false(enc, dec):
    """None and False mean different things here - 'not checked' against 'checked, wrong'.
    A playbook branching on hash_matches must be able to tell them apart."""
    e = enc.validate_rules(CORPUS["plain"])
    d = dec.decode_rules(e["b64"])
    assert d["hash_matches"] is None


def test_a_non_yara_payload_is_refused_and_still_shown(dec):
    """validate=False exists for exactly this: the payload the gate refuses is the one an
    operator most needs to look at."""
    pdf = base64.b64encode(b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n").decode()
    strict = dec.decode_rules(pdf)
    assert strict["ok"] is False
    assert any("pdf" in e.lower() for e in strict["errors"]), strict["errors"]
    assert "%PDF-" in strict["rules"], "the operator cannot see what it actually was"

    loose = dec.decode_rules(pdf, validate=False)
    assert loose["ok"] is True, "validate=False must return the text regardless"
    assert "%PDF-" in loose["rules"]


def test_empty_input_is_refused_with_an_actionable_message(dec):
    for value in ("", "   \n  ", None):
        d = dec.decode_rules(value)
        assert d["ok"] is False
        assert d["errors"]


# --- the two copies must never disagree about what a valid ruleset is --------------------

SHARED = ["_decode_bytes", "_looks_binary", "_brace_balance", "validate_rules"]


def _func_source(path, name):
    src = open(path, encoding="utf-8").read()
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.dump(ast.parse(ast.get_source_segment(src, node)))
    raise AssertionError("%s not found in %s" % (name, path))


@pytest.mark.parametrize("fn", SHARED)
def test_the_validation_shared_with_the_encoder_has_not_drifted(fn):
    """YaraRulesDecode carries a verbatim copy of the encoder's validation, because the
    tenant resolves no cross-script imports. If the two drifted, this automation could
    declare a dispatched pack invalid, or bless a pack the pre-dispatch gate would have
    refused - and either answer would be believed, because verification is the entire
    reason it exists.

    Compared as ASTs, so reformatting or a comment edit is allowed and a behaviour change
    is not.
    """
    assert _func_source(_ENCODE_PY, fn) == _func_source(_DECODE_PY, fn), (
        "%s has drifted between YaraRulesFromFile and YaraRulesDecode" % fn)


def test_the_shared_regexes_have_not_drifted():
    """The constants matter as much as the functions - _RULE_RE decides what counts as a
    rule declaration at all."""
    import re as _re
    for const in ("_RULE_RE", "_CONDITION_RE", "_REGEX_LITERAL_RE"):
        pats = []
        for path in (_ENCODE_PY, _DECODE_PY):
            src = open(path, encoding="utf-8").read()
            m = _re.search(r"(?m)^%s = re\.compile\((.+)\)$" % const, src)
            assert m, "%s not found in %s" % (const, path)
            pats.append(m.group(1))
        assert pats[0] == pats[1], "%s has drifted: %r vs %r" % (const, pats[0], pats[1])
