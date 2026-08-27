#!/usr/bin/env python3
"""YaraRulesFromFile: turn an operator-uploaded rules file into the scanner's yarafile input.

The scanner's own decode_yara_rules only checks base64-decodes + "contains the word rule"
(xdr_yara_scanner.py:429). That is deliberately permissive because it runs ON the endpoint,
where failing late is expensive. This automation runs BEFORE dispatch, once, so it validates
harder: a pack that cannot possibly compile should never reach a fleet of hosts.

It is also the one pack automation that needs NO tenant credentials - it reads a War Room
file and returns text. Giving it a credential block would add a fourth place to rotate keys
for no reason.
"""
import base64
import hashlib
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import _install_xsoar_stubs  # noqa: E402

demistomock, CommonServerPython = _install_xsoar_stubs()

_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                   "YaraRulesFromFile", "YaraRulesFromFile.py")


def _load():
    spec = importlib.util.spec_from_file_location("YaraRulesFromFile", _PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


R = _load()

GOOD = '''
rule Test_One
{
    meta:
        author = "x"
    strings:
        $a = "hello"
    condition:
        $a
}

rule Test_Two
{
    strings:
        $b = { 4D 5A }
    condition:
        $b at 0
}
'''


# ------------------------------------------------------------------ validation

def test_a_valid_pack_is_accepted_and_its_rules_named():
    v = R.validate_rules(GOOD)
    assert v["valid"] is True, v["errors"]
    assert v["rule_names"] == ["Test_One", "Test_Two"]
    assert v["rule_count"] == 2


def test_the_rule_hash_matches_what_the_SCANNER_will_compute():
    """The scanner hashes the DECODED text: sha256(yara_rule)[:12] (xdr_yara_scanner.py:2849),
    and that hash is the grouping key every consolidated dataset is named after. If this
    automation reports a different hash the operator cannot predict which dataset their scan
    lands in."""
    v = R.validate_rules(GOOD)
    assert v["rule_hash"] == hashlib.sha256(GOOD.encode("utf-8")).hexdigest()[:12]


def test_empty_and_whitespace_are_rejected():
    for bad in ("", "   \n\t  "):
        v = R.validate_rules(bad)
        assert v["valid"] is False
        assert any("empty" in e.lower() for e in v["errors"]), v["errors"]


def test_text_without_any_rule_declaration_is_rejected():
    v = R.validate_rules("this is just prose about yara rules")
    assert v["valid"] is False
    assert any("no yara rule" in e.lower() for e in v["errors"]), v["errors"]


def test_a_rule_missing_its_condition_is_rejected():
    """YARA requires a condition section. The scanner would accept this pack and every host
    would then fail to compile it - the expensive way to find out."""
    v = R.validate_rules('rule NoCondition {\n  strings:\n    $a = "x"\n}\n')
    assert v["valid"] is False
    assert any("condition" in e.lower() for e in v["errors"]), v["errors"]


def test_unbalanced_braces_are_rejected():
    v = R.validate_rules('rule Broken {\n  condition:\n    true\n')
    assert v["valid"] is False
    assert any("brace" in e.lower() for e in v["errors"]), v["errors"]


def test_a_pdf_is_rejected_with_a_message_naming_the_format():
    """The operator was told "upload your rules"; a PDF is the most likely wrong upload, and
    silently base64-ing its bytes would ship garbage to the fleet."""
    v = R.validate_rules("%PDF-1.7\n%\xe2\xe3\xcf\xd3\nrule x { condition: true }")
    assert v["valid"] is False
    assert any("pdf" in e.lower() for e in v["errors"]), v["errors"]


def test_binary_content_is_rejected_rather_than_encoded():
    v = R.validate_rules("rule x { condition: true }\n\x00\x01\x02binary\x00")
    assert v["valid"] is False
    assert any("binary" in e.lower() or "text" in e.lower() for e in v["errors"]), v["errors"]


def test_oversized_input_is_refused_before_encoding():
    v = R.validate_rules("rule x { condition: true }\n" + ("A" * 200), max_bytes=100)
    assert v["valid"] is False
    assert any("too large" in e.lower() for e in v["errors"]), v["errors"]


# ------------------------------------------------------------------ encoding

def test_the_b64_round_trips_to_the_exact_original_text():
    v = R.validate_rules(GOOD)
    assert base64.b64decode(v["b64"]).decode("utf-8") == GOOD


def test_the_b64_satisfies_the_scanners_own_decoder():
    """End-to-end contract: whatever this produces must survive decode_yara_rules unchanged."""
    import ast as _ast
    import base64 as _b64
    import re as _re
    scanner = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "xdr", "xdr_yara_scanner.py")
    src = open(scanner, encoding="utf-8").read()
    tree = _ast.parse(src)
    # ast, not a regex: a regex that stops at the next `def` also swallows any module-level
    # code between functions, which then fails on globals the scanner has and this test does not.
    wanted = {"_ensure_text", "_b64_to_text", "decode_yara_rules"}
    ns = {"base64": _b64, "re": _re}
    for node in tree.body:
        if isinstance(node, _ast.FunctionDef) and node.name in wanted:
            exec(compile(_ast.Module(body=[node], type_ignores=[]), scanner, "exec"), ns)
    missing = wanted - set(ns)
    assert not missing, "could not lift from the scanner: %s" % sorted(missing)
    v = R.validate_rules(GOOD)
    assert ns["decode_yara_rules"](v["b64"]) == GOOD
