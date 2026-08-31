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


# --------------------------------------------------------------- entry discovery
# None of this was covered before, which is why the gap survived: the script only ever
# looked at incident attachments, so a file uploaded straight into the War Room - the
# ordinary way - reported "no rules file found". The argument name was wrong too: every
# Cortex content script (CommonScripts/ReadFile, CommonScripts/UnzipFile) takes `entryID`.

def _reset(monkeypatch, context=None, entries=None, incident=None):
    monkeypatch.setattr(demistomock, "context", lambda: context or {}, raising=False)
    monkeypatch.setattr(demistomock, "incident", lambda: incident or {}, raising=False)
    monkeypatch.setattr(demistomock, "executeCommand",
                        lambda cmd, a=None: (entries or []) if cmd == "getEntries" else None,
                        raising=False)


def test_file_context_is_found(monkeypatch):
    """File.EntryID - where an uploaded file lands. Previously invisible to this script."""
    _reset(monkeypatch, context={"File": {"EntryID": "111@abc", "Name": "r.yar"}})
    assert R.find_rules_entry_id() == "111@abc"


def test_file_context_takes_the_newest_when_several(monkeypatch):
    """`File` becomes a LIST once more than one file is present; newest wins, so a
    corrected re-upload supersedes the broken one without anyone deleting it."""
    _reset(monkeypatch, context={"File": [{"EntryID": "old@1"}, {"EntryID": "new@2"}]})
    assert R.find_rules_entry_id() == "new@2"


def test_war_room_entry_is_found(monkeypatch):
    """getEntries + entry["ID"], the CommonScripts/UnzipFile pattern."""
    _reset(monkeypatch, entries=[{"ID": "1@x", "File": "notes.txt"},
                                 {"ID": "2@x", "File": "rules.yar"}])
    assert R.find_rules_entry_id() == "2@x"


def test_war_room_ignores_entries_that_are_not_files(monkeypatch):
    _reset(monkeypatch, entries=[{"ID": "1@x", "Contents": "just a note"}])
    assert R.find_rules_entry_id() is None


def test_attachment_still_works(monkeypatch):
    """The original path must keep working - it is how a playbook-attached file arrives."""
    _reset(monkeypatch, incident={"attachment": [{"entryID": "att@9"}]})
    assert R.find_rules_entry_id() == "att@9"


def test_file_context_wins_over_attachment(monkeypatch):
    """Most-specific source first; both can be populated at once."""
    _reset(monkeypatch, context={"File": {"EntryID": "ctx@1"}},
           incident={"attachment": [{"entryID": "att@1"}]})
    assert R.find_rules_entry_id() == "ctx@1"


def test_nothing_anywhere_returns_none(monkeypatch):
    _reset(monkeypatch)
    assert R.find_rules_entry_id() is None


def test_a_probe_that_raises_does_not_break_discovery(monkeypatch):
    """demisto.context() is not available in every execution context. A source that blows
    up must fall through to the next one rather than failing the whole run."""
    def boom():
        raise RuntimeError("no context here")
    monkeypatch.setattr(demistomock, "context", boom, raising=False)
    monkeypatch.setattr(demistomock, "executeCommand", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(demistomock, "incident",
                        lambda: {"attachment": [{"entryID": "att@fallback"}]}, raising=False)
    assert R.find_rules_entry_id() == "att@fallback"


def test_the_entry_argument_has_exactly_one_spelling(monkeypatch):
    """`entryID` is what every Cortex content script uses (ReadFile, UnzipFile), and it is
    the only spelling this script accepts. Carrying a second alias would put two arguments
    that do the same thing in front of an analyst, for no benefit - nothing ever consumed
    the old `entry_id` name."""
    import yaml as _y
    d = _y.safe_load(open(_PY[:-3] + ".yml"))
    names = {a["name"] for a in d["args"]}
    assert "entryID" in names, names
    assert "entry_id" not in names, "two names for one argument: %s" % sorted(names)
