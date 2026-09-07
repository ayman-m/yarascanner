#!/usr/bin/env python3
"""YaraRulesFromFile's `errors` list is CONTEXT, so it carries fields rather than sentences.

`errors` used to ship as a list of preformatted human sentences. A playbook that wanted to
act on a rejection - retry a too-large file with a bigger ceiling, tell "you uploaded a PDF"
from "your braces are unbalanced" - had no option but to substring match prose written for a
human. That is a contract nobody can change safely and nobody can rely on: reword one message
for clarity and every filter downstream silently stops matching, with no error anywhere. This
suite's own older file still does exactly that, with `any("pdf" in e.lower() for e in ...)`.

Worse, three of those sentences were the ONLY place a number appeared at all. To learn how
many braces short a file was, a caller had to parse "%d unclosed" out of a sentence that also
branches on the SIGN of the count. So each entry is an object now, `reason` is a CLOSED
vocabulary, and the numbers are fields.

Two properties pinned here that are not obvious:

  * validate_rules KEEPS returning sentences, and must. It is byte-identical to
    YaraRulesDecode's copy and tests/test_rules_decode.py compares the two by AST - the
    sentence is the contract shared between the pre-dispatch encoder and the post-dispatch
    verifier. main() translates on the way out, so what is pinned here is that the
    translation covers every branch: a reworded message has to fail a test rather than
    quietly become `unrecognised`.

  * NOTHING in `errors` may be a string. The old readable-output builder did
    `lines += ["  - %s" % e for e in result["errors"]]`, which does NOT raise when an element
    becomes a dict - it renders `- {'reason': 'empty', ...}` straight into the War Room. That
    line is gone; the assertions below keep both halves of that hazard closed.
"""
import importlib.util
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    FakeTenant, _install_xsoar_stubs, _run_automation,
)

demistomock, CommonServerPython = _install_xsoar_stubs()

_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                   "YaraRulesFromFile", "YaraRulesFromFile.py")
_YML = _PY[:-3] + ".yml"


def _load():
    spec = importlib.util.spec_from_file_location("YaraRulesFromFile", _PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


R = _load()

# _run_automation swaps a module's CoreApiClient out for the fake tenant and back. This is
# the one pack automation that touches no tenant API - it reads a War Room file and returns
# text - so it has no such attribute to swap. Give it an inert one rather than a private
# copy of the harness: the FakeTenant handed to _run below is never called, and the day this
# automation does grow a client, the harness is already the one driving it.
R.CoreApiClient = None

GOOD = '''
rule Test_One
{
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

_TMP = tempfile.mkdtemp(prefix="yara_rules_from_file_")


def _run(text, name="rules.yar", entry="42@abc", **args):
    """Drive main() over `text` as though it were the uploaded War Room file.

    `name=None` models the entry that carries no name - the case that used to be papered
    over with the entry id.
    """
    path = os.path.join(_TMP, "upload.bin")
    data = text.encode("utf-8") if isinstance(text, str) else text
    with open(path, "wb") as fh:
        fh.write(data)
    entry_file = {"path": path}
    if name is not None:
        entry_file["name"] = name
    demistomock.getFilePath = lambda eid, _f=entry_file: dict(_f)
    a = {"entryID": entry}
    a.update(args)
    return _run_automation(R, a, FakeTenant([]), pin_schema=False)


def _run_refused(text, **args):
    """main() refusing its ARGUMENTS, before it validates anything. Returns the message.

    The harness's return_error raises SystemExit, exactly as the platform ends a script, so
    an argument main() should refuse must never come back as a CommandResults at all.
    """
    with pytest.raises(SystemExit):
        _run(text, **args)
    assert CommonServerPython.errors, "main() accepted an argument it must refuse"
    return CommonServerPython.errors[-1]


# Every rejection branch validate_rules has, with the input that drives it and the reason
# code it must map to. `not_text` is unreachable through main() - read_entry always hands
# over bytes, and latin-1 decodes any byte sequence - so it is driven at the validator, which
# is where the sentences come from anyway.
BRANCHES = [
    ("not_text", 123, {}),
    ("empty", "   \n\t  ", {}),
    ("too_large", "rule x { condition: true }\n" + ("A" * 200), {"max_bytes": 100}),
    ("pdf", "%PDF-1.7\n%\xe2\xe3\xcf\xd3\nrule x { condition: true }", {}),
    ("binary", "rule x { condition: true }\n\x00\x01\x02binary\x00", {}),
    ("no_rules", "this is just prose about yara rules", {}),
    ("unbalanced_braces", "rule Broken {\n  condition:\n    true\n", {}),
    ("missing_condition", 'rule NoCondition {\n  strings:\n    $a = "x"\n}\n', {}),
]

_RECORD_KEYS = {"reason", "detail", "observed", "expected", "limit"}


# ------------------------------------------------------------------ the list holds objects

def test_every_error_is_an_object():
    """The whole point. One string among the objects is the silent failure mode - the old
    renderer would have printed it and the context would have carried it."""
    for reason, raw, kw in BRANCHES:
        if reason == "not_text":
            continue                       # unreachable through a file; covered below
        res = _run(raw, **{k: str(v) for k, v in kw.items()})
        assert res.outputs["errors"], "%s produced no error" % reason
        for entry in res.outputs["errors"]:
            assert isinstance(entry, dict), (
                "errors holds a bare %s - a playbook filtering on a field would silently "
                "match nothing: %r" % (type(entry).__name__, entry))


@pytest.mark.parametrize("reason,raw,kw", BRANCHES, ids=[b[0] for b in BRANCHES])
def test_an_error_record_carries_every_key_whatever_the_reason(reason, raw, kw):
    """Every entry carries every key even where one does not apply. A transformer filtering
    on a key that is only sometimes present matches nothing and reports no error."""
    recs = R._error_records(R.validate_rules(raw, **kw)["errors"])
    assert len(recs) == 1, recs
    rec = recs[0]
    assert set(rec) == _RECORD_KEYS, "error record shape drifted: %s" % sorted(rec)
    assert rec["reason"] == reason
    assert rec["detail"] and isinstance(rec["detail"], str)


# ------------------------------------------------------- the vocabulary stays closed

@pytest.mark.parametrize("reason,raw,kw", BRANCHES, ids=[b[0] for b in BRANCHES])
def test_no_validation_branch_falls_through_to_unrecognised(reason, raw, kw):
    """`unrecognised` exists so a message added to the validator cannot leak an undeclared
    code into a playbook. It must never be what a CURRENT branch produces - if this fails,
    a sentence was reworded and the mapping beside it was not."""
    rec = R._error_records(R.validate_rules(raw, **kw)["errors"])[0]
    assert rec["reason"] != "unrecognised", (
        "the validator's message no longer matches its signature: %r" % rec["detail"])
    assert rec["reason"] in R.ERROR_REASONS, (
        "undeclared reason %r - add it to ERROR_REASONS or use an existing one"
        % rec["reason"])


def test_an_unknown_message_is_labelled_rather_than_guessed():
    """The fallback itself. A code invented at a call site and never declared is exactly as
    unmatchable as the prose this replaced - it just looks like a contract."""
    rec = R._error_records(["Something nobody has written yet."])[0]
    assert rec["reason"] == "unrecognised"
    assert rec["detail"] == "Something nobody has written yet."
    assert rec["observed"] is None and rec["expected"] is None and rec["limit"] is None


def test_the_vocabulary_is_the_one_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out."""
    described = {o["contextPath"]: o["description"] for o in _yml()["outputs"]}
    for code in R.ERROR_REASONS:
        assert code in described["Yara.Rules.errors.reason"], (
            "reason %r is not in the yml's declared closed set" % code)


# ------------------------------------------------- the numbers are fields, not substrings

def test_too_large_reports_the_size_and_the_ceiling_as_numbers():
    o = _run("rule x { condition: true }\n" + ("A" * 200), max_bytes="100").outputs
    e = o["errors"][0]
    assert e["reason"] == "too_large"
    assert e["observed"] == o["size_bytes"] and e["observed"] > 100
    assert e["limit"] == 100 == o["max_bytes"]
    assert e["expected"] is None


def test_too_large_takes_its_numbers_from_the_facts_not_from_the_sentence():
    """The record used to be built by regexing the two numbers back out of the sentence
    main() had just produced, and the pattern could not express a NEGATIVE ceiling. It did
    not fail on one - it silently left `observed` and `limit` null on the one record whose
    whole purpose is to carry them, so a playbook filtering on `limit` to retry with a
    bigger ceiling matched nothing and reported no error.

    validate_rules treats every non-zero max_bytes as a live ceiling, so a negative one is a
    reachable input at the validator even now that main() refuses it at the door.
    """
    v = R.validate_rules("rule x { condition: true }\n", max_bytes=-5)
    assert v["errors"], "a negative ceiling must still reject - the premise of this test"

    rec = R._error_records(v["errors"], size_bytes=v["size_bytes"], max_bytes=-5)[0]
    assert rec["reason"] == "too_large"
    assert rec["observed"] == v["size_bytes"] and rec["observed"] > 0
    assert rec["limit"] == -5, (
        "the ceiling the run applied was dropped from the record: %r" % rec)

    # And the fallback, for a caller that hands over only the sentences: it has to read
    # every ceiling the validator will accept, not only the ones that look tidy.
    bare = R._error_records(v["errors"])[0]
    assert bare["observed"] == v["size_bytes"] and bare["limit"] == -5, (
        "the sentence-only path still loses both numbers: %r" % bare)


def test_a_negative_ceiling_is_refused_at_the_door():
    """It is not a smaller limit, it is one no file can be under: every possible upload is
    rejected as too large. That is an argument error, like a non-numeric one - not a
    validation result to hand an analyst who then re-uploads the same good file."""
    msg = _run_refused(GOOD, max_bytes="-5")
    assert "max_bytes" in msg and "negative" in msg
    assert "0" in msg, "the message must name the value that DOES disable the check"


def test_unbalanced_braces_reports_the_direction_as_a_sign():
    """The worst of the three: the direction was encoded in the WORDING - "2 unclosed" vs
    "2 unexpected closing" - so a caller had to branch on prose to learn the sign."""
    unclosed = _run("rule Broken {\n  condition:\n    true\n").outputs["errors"][0]
    assert unclosed["reason"] == "unbalanced_braces"
    assert unclosed["observed"] == 1 and unclosed["expected"] == 0

    extra = _run("rule Ok { condition: true }\n}\n}\n").outputs["errors"][0]
    assert extra["reason"] == "unbalanced_braces"
    assert extra["observed"] < 0, "an unexpected closing brace must read as negative"


def test_missing_condition_reports_both_counts():
    o = _run('rule A {\n  strings:\n    $a = "x"\n}\nrule B {\n  condition:\n    true\n}\n')
    e = o.outputs["errors"][0]
    assert e["reason"] == "missing_condition"
    assert e["expected"] == 2 and e["observed"] == 1
    assert e["limit"] is None


def test_a_reason_with_no_numbers_nulls_them_rather_than_inventing_zero():
    """0 is a claim. Null is the truth for a reason that never measured anything."""
    e = _run("this is just prose about yara rules").outputs["errors"][0]
    assert e["reason"] == "no_rules"
    assert e["observed"] is None and e["expected"] is None and e["limit"] is None


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    md = _run(GOOD).readable_output
    assert md.startswith("### YARA rules from file - ACCEPTED")
    assert "\n|---|---|\n" in md, "no markdown table in the output"
    assert "#### Rules in the pack" in md
    # the prose the tables replaced
    assert "Rules accepted from **" not in md
    assert "rule(s):" not in md


def test_a_rejection_renders_a_table_and_not_a_dict_repr():
    """The specific hazard: `"  - %s" % e` does not raise when `e` becomes a dict, it prints
    the repr. Nothing fails loudly, the War Room just fills with Python."""
    md = _run("").readable_output
    assert md.startswith("### YARA rules from file - REJECTED")
    assert "#### Rejected because" in md
    assert "| `empty` |" in md
    assert "'reason':" not in md and "{'" not in md, "a record repr leaked into the report"


# The branches that reach the rule-declaration scan. validate_rules returns at the FIRST
# failure, so a rejection reason says exactly how far the run got: these three ran the scan,
# and every other reason returned before it. Spelled out here rather than imported from the
# automation, so the classification itself is what this pins - a set the module got wrong
# would otherwise agree with itself.
_COUNTED = {"no_rules", "unbalanced_braces", "missing_condition"}


@pytest.mark.parametrize("reason,raw,kw",
                         [b for b in BRANCHES if b[0] != "not_text"],
                         ids=[b[0] for b in BRANCHES if b[0] != "not_text"])
def test_the_report_never_prints_a_count_that_was_never_taken(reason, raw, kw):
    """`Rules found: 0` was printed on all five branches that return BEFORE the declaration
    scan - so a PDF whose text contains `rule RealRule { condition: true }` was reported to
    the operator as holding no rules. 0 is a claim; nothing had counted anything.

    The error records already honour this - a reason that measured nothing nulls its numbers
    rather than inventing a zero - and the facts table beside them did not.
    """
    res = _run(raw, **{k: str(v) for k, v in kw.items()})
    md = res.readable_output
    if reason in _COUNTED:
        # Here the scan DID run, so whatever it found is a measurement - including the 0 on
        # `no_rules`, which is the one zero in this table that is the truth.
        assert "| **Rules found** | %s |" % format(res.outputs["rule_count"], ",d") in md
    else:
        assert res.outputs["rule_count"] == 0, "the fixture stopped exercising the 0 case"
        assert "| **Rules found** | 0 |" not in md, (
            "%s never counted anything, and the report says it counted none" % reason)
        assert "not counted" in md


def test_a_pdf_holding_a_real_rule_is_not_reported_as_holding_none():
    """The reviewer's reproduction, kept as its own case because the lie is legible in it:
    the text plainly contains a rule, and the War Room said there were zero."""
    res = _run("%PDF-1.7\n%\xe2\xe3\xcf\xd3\nrule RealRule { condition: true }\n")
    md = res.readable_output
    assert "### YARA rules from file - REJECTED" in md
    assert "| **Rules found** | 0 |" not in md
    assert "| `pdf` |" in md


def test_the_report_claims_no_ceiling_when_none_was_applied():
    """max_bytes=0 turns the size check off - validate_rules short-circuits on the falsy
    value and compares nothing - and the run then published 0 as "the ceiling this run
    judged the file against" and printed "against a 0 byte ceiling" for a file that PASSED.
    A 40-byte file that passed a zero-byte limit is not something that happened."""
    res = _run(GOOD, max_bytes="0")
    assert res.outputs["valid"] is True, "0 disables the check; it must not reject"
    assert res.outputs["max_bytes"] is None, (
        "no ceiling was applied, so there is none to publish: %r"
        % res.outputs["max_bytes"])
    md = res.readable_output
    assert "0 byte ceiling" not in md
    assert "against no ceiling" in md
    # and the ordinary case is untouched
    assert "against a 2,097,152 byte ceiling" in _run(GOOD).readable_output


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see."""
    res = _run(GOOD)
    o, md = res.outputs, res.readable_output
    assert "| **Rules found** | %d |" % o["rule_count"] in md
    assert "| **Ruleset hash** | `%s` |" % o["rule_hash"] in md
    assert "| **Summary target** | `%s` |" % o["summary_target"] in md
    assert "| **Full target** | `%s` |" % o["full_target"] in md
    assert "| **Entry** | `%s` |" % o["entry_id"] in md
    assert "%s bytes, against a %s byte ceiling" % (format(o["size_bytes"], ",d"),
                                                    format(o["max_bytes"], ",d")) in md


def test_a_pipe_in_a_cell_cannot_shear_the_table():
    """Rule names come from a ruleset and the detail sentence quotes what was uploaded. One
    unescaped pipe and every row below it loses a column - silently, markdown does not
    error."""
    row = R._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


def test_the_markdown_truncates_but_the_context_does_not():
    """A 300-rule pack must not push the verdict off the top of the War Room - and must not
    lose a rule name to do it."""
    n = R._MD_ROW_CAP + 10
    text = "\n".join("rule R%03d { condition: true }" % i for i in range(n))
    res = _run(text)
    assert res.outputs["rule_count"] == n
    assert len(res.outputs["rule_names"]) == n
    assert res.readable_output.count("| R0") == R._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.Rules.rule_names`" in res.readable_output


# ------------------------------------------------------ what a playbook already splices

def test_valid_stays_a_scalar_bool_and_b64_a_scalar_string():
    """playbook-YARA_Scanner_Runner isEqualStrings Yara.Rules.valid and splices
    Yara.Rules.b64 into a hand-built JSON literal. Neither may become a structure."""
    ok = _run(GOOD).outputs
    assert ok["valid"] is True and isinstance(ok["b64"], str) and ok["b64"]
    bad = _run("").outputs
    assert bad["valid"] is False and bad["b64"] == ""


def test_rule_names_stay_plain_strings():
    """They are identifiers, not prose - they encode no second fact, and the renderer joins
    them. A list of scan_ids or rule names is DATA; it needs no conversion."""
    names = _run(GOOD).outputs["rule_names"]
    assert names == ["Test_One", "Test_Two"]
    assert all(isinstance(n, str) for n in names)


def test_valid_is_true_exactly_when_errors_is_empty():
    """The relationship the yml documents. Both are published; this is what makes keeping
    both honest rather than a second copy nobody can rank."""
    for reason, raw, kw in BRANCHES:
        if reason == "not_text":
            continue
        o = _run(raw, **{k: str(v) for k, v in kw.items()}).outputs
        assert o["valid"] is False and o["errors"]
    o = _run(GOOD).outputs
    assert o["valid"] is True and o["errors"] == []


def test_rule_count_is_always_the_length_of_rule_names():
    for text in (GOOD, "this is just prose", "rule Broken {\n  condition:\n    true\n"):
        o = _run(text).outputs
        assert o["rule_count"] == len(o["rule_names"])


# --------------------------------------------------------------- the honest filename

def test_the_filename_is_null_rather_than_the_entry_id():
    """It used to silently become the entry id, which the War Room then printed as though it
    were a filename - "Rules accepted from **111@abc**" - and no caller could tell the two
    apart."""
    o = _run(GOOD, name=None, entry="111@abc").outputs
    assert o["filename"] is None
    assert o["entry_id"] == "111@abc"
    named = _run(GOOD, name="pack.yar").outputs
    assert named["filename"] == "pack.yar"


def test_the_report_says_so_rather_than_printing_an_entry_id_as_a_name():
    md = _run(GOOD, name=None, entry="111@abc").readable_output
    assert "_the entry carries no filename_" in md
    assert "| **File** | `111@abc` |" not in md
    assert "| **Entry** | `111@abc` |" in md


# ------------------------------------------------- facts that were computed but not published

def test_the_consolidation_targets_are_published_not_only_printed():
    """They existed only inside a War Room sentence, so a playbook that wanted the dataset
    its scan lands in had to re-derive this pack's naming convention or substring-parse the
    report."""
    o = _run(GOOD).outputs
    assert o["summary_target"] == "yara_scanner_summary_v4_rules_%s" % o["rule_hash"]
    assert o["full_target"] == "yara_scanner_full_v4_rules_%s" % o["rule_hash"]


def test_a_rejected_file_names_no_target_at_all():
    """No hash, no dataset. An invented name would point a dashboard at something that can
    never exist."""
    o = _run("").outputs
    assert o["rule_hash"] == "" and o["summary_target"] == "" and o["full_target"] == ""


def test_the_ceiling_is_reported_even_when_the_file_passed():
    """max_bytes appeared only inside the too_large sentence, so a run that PASSED never
    said which limit it passed."""
    assert _run(GOOD).outputs["max_bytes"] == R.DEFAULT_MAX_BYTES
    assert _run(GOOD, max_bytes="900000").outputs["max_bytes"] == 900000


def test_the_context_is_cleared_before_it_is_written():
    """List-valued context is APPENDED to across calls in one investigation, so a second
    upload in the same issue would otherwise merge both files' rule names."""
    res = _run(GOOD)
    assert ("DeleteContext", {"key": "Yara.Rules"}) in demistomock.commands
    assert res.outputs_prefix == "Yara.Rules"


# ------------------------------------------------------ the yml contract is not fiction

def _yml():
    import yaml
    with open(_YML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _declared_outputs():
    return [o["contextPath"][len("Yara.Rules."):] for o in _yml()["outputs"]]


def _scenarios():
    """No single run populates both a valid result and every error shape, and requiring that
    would only prove something about a contrived file."""
    out = [_run(GOOD).outputs]
    for reason, raw, kw in BRANCHES:
        if reason == "not_text":
            continue
        out.append(_run(raw, **{k: str(v) for k, v in kw.items()}).outputs)
    return out


def test_the_yml_says_what_a_disabled_ceiling_publishes():
    """A null under `type: Number` is precisely the thing a playbook author has to read in
    the contract rather than discover in a run - and the argument that produces it, plus the
    one value main() now refuses, belong in the argument's own description."""
    described = {o["contextPath"]: o["description"] for o in _yml()["outputs"]}
    ceiling = described["Yara.Rules.max_bytes"]
    assert "null" in ceiling.lower() and "0" in ceiling
    arg = {a["name"]: a.get("description", "") for a in _yml()["args"]}["max_bytes"]
    assert "0" in arg and "negative" in arg.lower()


def test_the_yml_does_not_let_a_zero_rule_count_read_as_a_finding():
    """rule_count stays len(rule_names) on every path - the validator owns that and it is
    shared byte-for-byte with the decoder. So the contract has to say which zeros are a
    measurement, the way the report now does."""
    described = {o["contextPath"]: o["description"] for o in _yml()["outputs"]}
    assert "nothing was counted" in described["Yara.Rules.rule_count"]


def test_every_declared_output_is_actually_produced():
    """The pack's own gate for this flattens a contextPath by stripping one prefix, so it
    cannot express `errors.reason`. Declaring the object keys is the whole point of
    declaring them, so the check has to walk into the list."""
    scenarios = _scenarios()
    missing = []
    for path in _declared_outputs():
        head, _, leaf = path.partition(".")
        if not leaf:
            if not any(head in o for o in scenarios):
                missing.append(path)
            continue
        seen = False
        for o in scenarios:
            for entry in o.get(head) or []:
                seen = True
                if leaf not in entry:
                    missing.append("%s (absent from a %s entry: %s)"
                                   % (path, head, sorted(entry)))
        if not seen:
            missing.append("%s (no scenario ever populated %s)" % (path, head))
    assert not missing, "declared but not produced:\n  " + "\n  ".join(sorted(set(missing)))


def test_nothing_is_produced_that_the_yml_does_not_declare():
    """The other direction. An undeclared key is invisible in the console's output picker, so
    a playbook author never learns it exists."""
    declared = set(_declared_outputs())
    for o in _scenarios():
        undeclared = sorted(set(o) - declared)
        assert not undeclared, "produced but never declared in the yml: %s" % undeclared
