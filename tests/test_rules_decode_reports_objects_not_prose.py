#!/usr/bin/env python3
"""YaraRulesDecode's `errors` list is CONTEXT, so it carries fields rather than sentences.

It used to be a list of full English sentences with no reason code, no operands and nothing
machine-readable in it at all. A playbook wanting to tell "the operator uploaded a PDF" from
"the payload is 3 MB" from "someone pasted URL-safe base64" from "the braces do not balance"
had one option: substring-match prose written for a human. That is a contract nobody can
change safely and nobody can rely on - reword one message for clarity and every filter
downstream silently stops matching, with no error anywhere.

So each entry is an object now and `reason` is a CLOSED vocabulary. These tests pin the
shapes, pin that the vocabulary is closed, and pin that the yml documents the same set the
code emits - because the value of a closed set is entirely in it staying closed, and the yml
is the only place a playbook author ever reads it.

Three properties here are less obvious and matter more:

  * THE VALIDATOR'S SENTENCES ARE CLASSIFIED, NOT REWRITTEN. validate_rules is a verbatim
    copy of YaraRulesFromFile's, pinned to it byte-for-byte (AST, docstring included) by
    test_rules_decode.py. Giving its appends reason codes here would drift it from the very
    function this automation exists to agree with. So the sentences are matched against
    markers instead - and test_every_sentence_the_validator_can_emit_maps_to_a_reason walks
    the appends out of the source with ast, so a reworded message fails HERE, loudly, rather
    than silently landing in context as `unclassified`.

  * THE OPERANDS ARE RECOMPUTED, NOT PARSED. "%d bytes against a %d byte limit" carries two
    numbers a caller needs; reading them back out of the sentence would be a second contract
    on the same prose. The records recompute them from the same expressions that produced
    the sentence, so the number on the record cannot disagree with the number beside it.

  * `ok` IS EXACTLY `not errors`, AND A HASH MISMATCH DOES NOT BREAK THAT. The mismatch is a
    finding about provenance, not about the rules - folding it into `errors` would leave the
    one invariant a playbook can rely on quietly false.
"""
import ast
import base64
import importlib.util
import io
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pytest  # noqa: E402
from test_pack_data_management import (  # noqa: E402
    _install_xsoar_stubs, _run_automation,
)

_install_xsoar_stubs()

# Registered in sys.modules by the installer above. Needed directly because _run_automation
# asserts no return_error was raised, so the argument guards cannot be driven through it.
import demistomock as demisto            # noqa: E402
import CommonServerPython as csp         # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DIR = os.path.join(_REPO, "xdr", "Packs", "YaraDatasetManagement", "Scripts",
                    "YaraRulesDecode")
_PY = os.path.join(_DIR, "YaraRulesDecode.py")
_YML = os.path.join(_DIR, "YaraRulesDecode.yml")


def _load():
    spec = importlib.util.spec_from_file_location("YaraRulesDecode_objects", _PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


D = _load()

# This automation touches no tenant API - it decodes text - so it has no CoreApiClient of its
# own. _run_automation saves and restores that attribute around main(), so the name has to
# exist for the shared fixture to drive it; nothing ever calls it.
D.CoreApiClient = None

PLAIN = 'rule Plain {\n  condition:\n    true\n}\n'


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _run(**args):
    """main() through the pack's own fixture. It returns whatever return_results was handed,
    which here is a LIST - the automation can attach the decoded rules as a second entry."""
    results = _run_automation(D, args, None, pin_schema=False)
    assert isinstance(results, list), type(results)
    return results[0]


def _refusal(**args):
    """main() driven to a return_error, and the message it refused with.

    _run_automation asserts no error was raised, so an ARGUMENT GUARD cannot be exercised
    through it - which is why the guards added for max_bytes needed their own driver. The
    harness's return_error raises SystemExit, standing in for the way return_error aborts a
    script on a tenant.
    """
    demisto.args_value = dict(args)
    demisto.commands = []
    del csp.results[:]
    del csp.errors[:]
    with pytest.raises(SystemExit):
        D.main()
    assert len(csp.errors) == 1, csp.errors
    assert not csp.results, (
        "the run published a result as well as refusing - a playbook would read context "
        "written by a run that errored: %r" % csp.results)
    return csp.errors[0]


def _fact(md, key):
    """One row of the facts table, by its bolded label. Exactly one, or the caller is
    asserting against a row that does not exist."""
    rows = [ln for ln in md.splitlines() if ln.startswith("| **%s** |" % key)]
    assert len(rows) == 1, "no single %r row in:\n%s" % (key, md)
    return rows[0]


# Every refusal this automation can actually reach, keyed by the reason it must report.
# not_text and invalid_b64 are absent on purpose and covered separately: _decode_bytes falls
# back to latin-1, which decodes any byte string, and decode_b64's alphabet and padding
# repairs mean nothing that reaches base64.b64decode can raise. Both are defensive branches,
# so they are pinned through the classifier and the vocabulary rather than through a payload.
SCENARIOS = {
    "no_input": {"b64": "   \n  "},
    "urlsafe_b64": {"b64": base64.urlsafe_b64encode(b"\xfb\xff\xfe rule").decode()},
    "bad_alphabet": {"b64": _b64(PLAIN)[:8] + "!!*(" + _b64(PLAIN)[8:]},
    "empty": {"b64": _b64("   \n\t  ")},
    "too_large": {"b64": _b64(PLAIN), "max_bytes": "10"},
    "pdf": {"b64": _b64("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\n")},
    "binary": {"b64": base64.b64encode(b"\x00\x01\x02rule X {}").decode()},
    "no_rules": {"b64": _b64("just some notes about rules, no declarations\n")},
    "unbalanced_braces": {"b64": _b64('rule Open {\n  condition:\n    true\n')},
    "missing_conditions": {"b64": _b64('rule A {\n  condition:\n    true\n}\n'
                                       'rule B {\n  strings:\n    $a = "x"\n}\n')},
}

RECORD_KEYS = {"reason", "detail", "stage", "observed", "limit"}


# ------------------------------------------------------------------ the errors list

@pytest.mark.parametrize("expected", sorted(SCENARIOS))
def test_every_entry_in_errors_is_an_object_carrying_the_whole_key_set(expected):
    """The whole point. One string among the objects is the silent failure mode, and so is
    a key that only some entries carry - a transformer filtering on a sometimes-absent field
    matches nothing and reports no error."""
    res = _run(**SCENARIOS[expected])
    errors = res.outputs["errors"]
    assert errors, "%s should have been refused" % expected
    for e in errors:
        assert isinstance(e, dict), (
            "errors holds a bare %s - a playbook filtering on a field would silently match "
            "nothing: %r" % (type(e).__name__, e))
        assert set(e) == RECORD_KEYS, "error record shape drifted: %s" % sorted(e)
        assert e["reason"] and e["detail"] and e["stage"]
    assert [e["reason"] for e in errors] == [expected]


def test_the_stage_says_where_the_payload_was_refused():
    """"decode" means re-copy the payload, "validate" means fix the ruleset. Not derivable
    from the reason - not_text can arise at either stage - which is why it is its own key."""
    for reason in ("no_input", "urlsafe_b64", "bad_alphabet"):
        assert _run(**SCENARIOS[reason]).outputs["errors"][0]["stage"] == "decode"
    for reason in ("empty", "too_large", "pdf", "binary", "no_rules", "unbalanced_braces",
                   "missing_conditions"):
        assert _run(**SCENARIOS[reason]).outputs["errors"][0]["stage"] == "validate"
    for reason in sorted(SCENARIOS):
        for e in _run(**SCENARIOS[reason]).outputs["errors"]:
            assert e["stage"] in D.ERROR_STAGES, "undeclared stage %r" % e["stage"]


def test_a_quantitative_refusal_carries_its_operands_rather_than_burying_them_in_prose():
    """The three refusals that compare two numbers put both on the record. Recomputed from
    the same expressions that produced the sentence, so they cannot disagree with it."""
    size = len(PLAIN.encode("utf-8"))
    big = _run(**SCENARIOS["too_large"]).outputs
    assert big["errors"][0]["observed"] == size == big["size_bytes"]
    assert big["errors"][0]["limit"] == 10 == big["max_bytes"]

    brace = _run(**SCENARIOS["unbalanced_braces"]).outputs["errors"][0]
    assert brace["observed"] == 1, "positive depth is one unclosed block"
    assert brace["limit"] == 0, "the balance every ruleset must reach"
    closing = _run(b64=_b64('rule A {\n  condition:\n    true\n}\n}\n')).outputs["errors"][0]
    assert closing["reason"] == "unbalanced_braces"
    assert closing["observed"] == -1, "the sign is what tells the two cases apart"

    cond = _run(**SCENARIOS["missing_conditions"]).outputs
    assert cond["errors"][0]["observed"] == 1, "one `condition:` section was found"
    assert cond["errors"][0]["limit"] == 2 == cond["rule_count"], "two rules needed one each"


def test_a_refusal_that_compares_nothing_still_carries_both_operand_keys():
    """None, not absent. A filter on `limit` must match every entry or it is not a filter."""
    for reason in ("no_input", "urlsafe_b64", "bad_alphabet", "empty", "pdf", "binary",
                   "no_rules"):
        e = _run(**SCENARIOS[reason]).outputs["errors"][0]
        assert e["observed"] is None and e["limit"] is None, (reason, e)


# ------------------------------------------------------- the vocabulary stays closed

def test_every_reason_emitted_is_in_the_declared_vocabulary():
    """A reason invented at a call site and never declared is exactly as unmatchable as the
    prose it replaced - it just looks like a contract."""
    for name, args in sorted(SCENARIOS.items()):
        for e in _run(**args).outputs["errors"]:
            assert e["reason"] in D.ERROR_REASONS, (
                "undeclared reason %r from %s - add it to ERROR_REASONS or use an existing "
                "one" % (e["reason"], name))
    assert set(SCENARIOS) | {"not_text", "invalid_b64", "unclassified"} \
        == set(D.ERROR_REASONS), (
        "ERROR_REASONS and the scenarios below have drifted apart: %s"
        % sorted(set(SCENARIOS) ^ set(D.ERROR_REASONS)))


def _validator_sentences():
    """Every string literal validate_rules can append to its errors list, lifted out of the
    source. Reading the AST rather than driving the function is deliberate: one of these
    branches (not text in any encoding) is unreachable with real bytes, because _decode_bytes
    falls back to latin-1 - and an unreachable branch is exactly the one whose wording drifts
    unnoticed."""
    src = io.open(_PY, encoding="utf-8").read()
    fn = [n for n in ast.parse(src).body
          if isinstance(n, ast.FunctionDef) and n.name == "validate_rules"]
    assert fn, "validate_rules is gone from %s - this test is stale" % _PY
    out = []
    for node in ast.walk(fn[0]):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"):
            continue
        arg = node.args[0]
        while isinstance(arg, ast.BinOp):      # "... %d ..." % (operands)
            arg = arg.left
        assert isinstance(arg, ast.Constant), ast.dump(arg)
        out.append(arg.value)
    return out


def test_every_sentence_the_validator_can_emit_maps_to_a_reason():
    """The drift gate for the half of this vocabulary that cannot own its own reason codes.

    validate_rules is byte-pinned to YaraRulesFromFile's copy, so its sentences are matched
    rather than replaced. Reword one there and propagate it here and the gate in
    test_rules_decode.py stays green while every record silently becomes `unclassified` -
    unless this fails first, which is its entire job.
    """
    sentences = _validator_sentences()
    assert len(sentences) == 8, "validate_rules gained or lost a refusal: %s" % sentences
    for s in sentences:
        reason = D._classify_validation_error(s)
        assert reason != "unclassified", (
            "no marker matches this validator sentence any more, so it would reach context "
            "as `unclassified`: %r" % s)
        assert reason in D.ERROR_REASONS, reason
    assert len({D._classify_validation_error(s) for s in sentences}) == 8, (
        "two validator sentences classify to the same reason: %s"
        % sorted((D._classify_validation_error(s), s) for s in sentences))


def test_an_unrecognised_sentence_is_named_rather_than_guessed():
    """The fallback is a declared code, not a crash and not a plausible-looking wrong one."""
    assert D._classify_validation_error("something nobody has ever written") == "unclassified"
    assert "unclassified" in D.ERROR_REASONS


def _declared_outputs():
    import yaml
    with io.open(_YML, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return {o["contextPath"][len("Yara.RulesDecoded."):]: o for o in doc["outputs"]}


def test_the_vocabulary_is_the_one_the_yml_documents():
    """The yml is the contract a playbook author reads. If it and the code disagree, the
    author is the one who finds out - in production."""
    described = _declared_outputs()["errors.reason"]["description"]
    for code in D.ERROR_REASONS:
        assert code in described, (
            "reason %r is not in the yml's declared closed set" % code)
    listed = re.search(r"safe to match on in a playbook: ([^.]+)\.", described)
    assert listed, "the yml no longer spells the closed set out: %r" % described
    assert {c.strip() for c in listed.group(1).split(",")} == set(D.ERROR_REASONS), (
        "the yml names a different set than the code emits")
    stages = _declared_outputs()["errors.stage"]["description"]
    for stage in D.ERROR_STAGES:
        assert '"%s"' % stage in stages, "stage %r is not documented" % stage


# ---------------------------------------------------- the keys that are NOT duplicates

def test_ok_is_exactly_the_absence_of_errors_and_a_hash_mismatch_does_not_touch_it():
    """Both halves of the documented relationship. `ok` is the branch key, `errors` says why;
    a mismatch is a finding about provenance and must not make the rules look invalid."""
    for name, args in sorted(SCENARIOS.items()):
        o = _run(**args).outputs
        assert o["ok"] is False and o["errors"], name
    good = _run(b64=_b64(PLAIN), expected_hash="deadbeefcafe").outputs
    assert good["ok"] is True and good["errors"] == []
    assert good["hash_matches"] is False, "the mismatch must still be reported"


def test_hash_matches_keeps_the_third_state_a_caller_could_not_re_derive():
    """not checked / checked-and-wrong / checked-and-right. A playbook comparing the two hash
    fields itself gets the first two confused, which is why the verdict is computed here."""
    assert _run(b64=_b64(PLAIN)).outputs["hash_matches"] is None
    live = _run(b64=_b64(PLAIN)).outputs["rule_hash"]
    assert _run(b64=_b64(PLAIN), expected_hash=live.upper()).outputs["hash_matches"] is True
    assert _run(b64=_b64(PLAIN), expected_hash="x" * 12).outputs["hash_matches"] is False


def test_the_count_beside_the_list_is_the_length_of_the_list():
    """rule_count stays because the house convention keeps a count beside its list - so it
    has to be exactly that, on every path, or the yml's claim is false."""
    many = "".join('rule R%d {\n  condition:\n    true\n}\n\n' % i for i in range(9))
    for args in [{"b64": _b64(PLAIN)}, {"b64": _b64(many)}] + list(SCENARIOS.values()):
        o = _run(**args).outputs
        assert o["rule_count"] == len(o["rule_names"])


def test_rules_truncated_explains_the_gap_between_size_bytes_and_the_text_it_describes():
    """size_bytes is the WHOLE decoded size; `rules` is cut to 4000 characters on a failure.
    Without a flag, a caller doing len(rules) gets a number that disagrees with size_bytes
    and nothing in the context explains why."""
    big = "notes, but no rule declarations anywhere\n" * 300
    o = _run(b64=_b64(big)).outputs
    assert o["errors"][0]["reason"] == "no_rules"
    assert o["rules_truncated"] is True
    assert len(o["rules"]) == D._FAILED_RULES_CHARS < o["size_bytes"] == len(big)

    whole = _run(b64=_b64(PLAIN)).outputs
    assert whole["rules_truncated"] is False
    assert len(whole["rules"].encode("utf-8")) == whole["size_bytes"]


def test_the_settings_that_change_what_ok_means_reach_the_context():
    """validate=false is the mode that returns text the gate would refuse. A playbook reading
    ok=true could not previously tell whether the gate ran at all."""
    strict = _run(b64=_b64(PLAIN), max_bytes="4096").outputs
    assert strict["validated"] is True and strict["max_bytes"] == 4096

    loose = _run(b64=SCENARIOS["pdf"]["b64"], validate="false").outputs
    assert loose["ok"] is True and loose["errors"] == []
    assert loose["validated"] is False
    assert loose["max_bytes"] == 0, "no ceiling ran, so reporting one would be a claim"
    assert "%PDF-" in loose["rules"]


# ------------------------------------------------------------------- the War Room side

def test_the_readable_output_is_markdown():
    res = _run(b64=SCENARIOS["too_large"]["b64"], max_bytes="10")
    md = res.readable_output
    assert md.startswith("### YARA rules decode - REFUSED")
    assert "\n|---|---|\n" in md, "no markdown table in the output"
    assert "#### Problems" in md
    assert "| validate | `too_large` |" in md
    # the prose the table replaced
    assert "Could NOT decode this payload" not in md
    assert "\n  - " not in md, "an error is still being rendered as an indented bullet"

    ok = _run(b64=_b64(PLAIN)).readable_output
    assert ok.startswith("### YARA rules decode - DECODED")
    assert "#### Rules decoded" in ok and "#### Decoded text" in ok


def test_the_readable_output_and_the_context_cannot_disagree():
    """The report is rendered FROM the result dict. Pinning that means a number can never be
    formatted into the War Room from an expression the context did not also see."""
    res = _run(b64=_b64(PLAIN), expected_hash="deadbeefcafe", max_bytes="4096")
    o, md = res.outputs, res.readable_output
    assert "| **Decoded size** | %s bytes |" % format(o["size_bytes"], ",d") in md
    assert "| **Rules found** | %d |" % o["rule_count"] in md
    assert "| **Ruleset hash** | `%s` |" % o["rule_hash"] in md
    assert "| **Expected hash** | `%s` |" % o["expected_hash"] in md
    assert "| **Structural validation** | applied, against a %s byte ceiling |" \
        % format(o["max_bytes"], ",d") in md
    assert o["rule_names"][0] in md
    # the mismatch is stated in the table it is a field of, not in a sentence beside it
    assert "MISMATCH" in md and o["rule_hash"] in md


def test_an_error_record_reaches_the_report_as_a_table_row_not_a_concatenated_string():
    """The hazard this renderer replaced: `out += ["  " + s for s in items]` raises
    TypeError the moment an element is a dict, which is what every element is now."""
    md = _run(**SCENARIOS["missing_conditions"]).readable_output
    row = [ln for ln in md.splitlines() if "`missing_conditions`" in ln]
    assert len(row) == 1 and row[0].startswith("| validate |"), md
    assert row[0].count("|") == 6, "the record lost a column: %s" % row[0]


def test_the_markdown_truncates_but_the_context_does_not():
    """A 60-rule ruleset must not push the hash and the verdict off the top of the War Room -
    and must not lose a rule name to do it."""
    many = "".join('rule R%d {\n  condition:\n    true\n}\n\n' % i for i in range(60))
    res = _run(b64=_b64(many))
    assert len(res.outputs["rule_names"]) == 60
    rows = [ln for ln in res.readable_output.splitlines()
            if re.match(r"^\| \d+ \| R\d+ \|$", ln)]
    assert len(rows) == D._MD_ROW_CAP
    assert "and 10 more - the full list is in `Yara.RulesDecoded.rule_names`" \
        in res.readable_output


def test_the_report_says_how_much_of_the_text_it_is_showing():
    """The two caps differ - 4000 in context, 3000 in the report - so the report has to name
    the one it applied rather than leave two amounts of the same text under one name."""
    big = 'rule Big {\n  strings:\n    $a = "%s"\n  condition:\n    $a\n}\n' % ("x" * 5000)
    res = _run(b64=_b64(big))
    o, md = res.outputs, res.readable_output
    assert o["ok"] is True and o["rules_truncated"] is False
    assert "showing %s of the %s characters `Yara.RulesDecoded.rules` holds" \
        % (format(D._MD_RULES_CHARS, ",d"), format(len(o["rules"]), ",d")) in md


def test_a_pipe_in_a_cell_cannot_shear_the_table():
    """Detail sentences carry a decoder's exception text, which is not this pack's to
    sanitise. One unescaped pipe and every row below it loses a column, silently."""
    row = D._md_table(["a", "b"], [("we|ird", "fine")])
    assert "we\\|ird" in row
    assert len(row.splitlines()) == 3, "the pipe split the row"


# --------------------------------------------- a row must not state what did not happen
#
# Everything below is one property in three places: the report may only claim what the
# result dict actually says. Each of these rendered a confident sentence about a step that
# had not run - the exact failure this renderer was rewritten to end, and worse than the
# prose it replaced, because a table reads as measured.


def test_a_disabled_size_ceiling_is_not_reported_as_a_zero_byte_ceiling():
    """max_bytes=0 does not set a ceiling of zero - it removes the ceiling.

    validate_rules guards its size check with `if max_bytes and ...`, so a falsy value
    short-circuits it and NOTHING is compared. The row used to read "applied, against a 0
    byte ceiling" on that path, which is a comparison that never happened - a 37-byte payload
    passing "against 0" while the gate ran with no size check at all. Rendered from
    `validated` alone, the row could not tell the two apart; it is derived from the same
    condition the validator applies now.
    """
    res = D.decode_rules(_b64(PLAIN), validate=True, max_bytes=0)
    assert res["ok"] is True and res["validated"] is True and res["max_bytes"] == 0
    row = _fact(D.render_decode_markdown(res), "Structural validation")
    assert "against a 0 byte ceiling" not in row, (
        "the report states a ceiling nothing was compared against: %s" % row)
    assert "NO size ceiling" in row and "max_bytes=0" in row, row

    # The other two states still read as themselves - this is a three-way split, not a
    # rewrite of the row.
    ran = D.decode_rules(_b64(PLAIN), validate=True, max_bytes=4096)
    assert "applied, against a 4,096 byte ceiling" in _fact(
        D.render_decode_markdown(ran), "Structural validation")
    skipped = D.decode_rules(_b64(PLAIN), validate=False)
    assert "SKIPPED - validate=false" in _fact(
        D.render_decode_markdown(skipped), "Structural validation")


def test_main_refuses_a_max_bytes_that_could_not_be_a_ceiling():
    """0 and negatives parse as whole numbers and are still not ceilings.

    0 disables the size check while reading like a strict setting; a negative refuses EVERY
    payload, a valid ruleset included, as too_large against a limit nothing can be under -
    and used to publish that nonsense number into playbook-readable context twice, as
    max_bytes and as errors[].limit. Both are argument mistakes, so they are refused where
    the other arguments are.
    """
    for value in ("0", "-1", "-2097152"):
        msg = _refusal(b64=_b64(PLAIN), max_bytes=value)
        assert "max_bytes must be a positive number of bytes" in msg, msg
        assert repr(value) in msg, "the refusal does not echo what was passed: %s" % msg

    # ... and the guard has not swallowed a usable ceiling.
    assert _run(b64=_b64(PLAIN), max_bytes="4096").outputs["max_bytes"] == 4096
    assert _run(b64=_b64(PLAIN)).outputs["max_bytes"] == D.DEFAULT_MAX_BYTES


def test_the_hash_check_row_tells_not_requested_from_nothing_to_compare():
    """hash_matches has one null state and two ways of reaching it.

    "not requested - no expected_hash was given" is false on the second: a payload that was
    refused before it could be hashed leaves rule_hash empty even though an expected_hash was
    supplied - and the report printed that denial in the row directly under one showing the
    very hash it said had not been given.
    """
    res = _run(b64=SCENARIOS["pdf"]["b64"], expected_hash="deadbeefcafe")
    o, md = res.outputs, res.readable_output
    assert o["hash_matches"] is None and o["rule_hash"] == ""
    assert o["expected_hash"] == "deadbeefcafe"
    row = _fact(md, "Hash check")
    assert "no expected_hash was given" not in row, (
        "the row denies the expected_hash printed directly above it: %s" % row)
    assert "NOT CHECKED" in row and o["expected_hash"] in row, row

    # The genuinely-not-requested case still says so, and a real comparison still reports.
    assert "not requested - no expected_hash was given" in _fact(
        _run(b64=_b64(PLAIN)).readable_output, "Hash check")
    assert "MISMATCH" in _fact(
        _run(b64=_b64(PLAIN), expected_hash="deadbeefcafe").readable_output, "Hash check")


def test_a_backtick_run_in_the_ruleset_cannot_close_the_code_fence_early():
    """The decoded text is operator-supplied content inside a markdown fence.

    A fenced block ends at the first line whose fence is at least as long as the opening one,
    so a ruleset carrying ``` - in a comment, or because it was pasted out of a markdown
    document - closed the bare ``` early: the rest of the ruleset rendered as prose and a
    stray fence dangled after it, with nothing saying the War Room entry was no longer the
    payload. The fence outruns anything in the body now.
    """
    rules = ('rule Fenced {\n'
             '  /*\n```\n  lifted out of a markdown document\n  */\n'
             '  strings:\n    $a = "``````"\n'
             '  condition:\n    $a\n}\n')
    res = _run(b64=_b64(rules))
    assert res.outputs["ok"] is True, res.outputs["errors"]
    lines = res.readable_output.split("#### Decoded text\n", 1)[1].splitlines()

    fence = lines[0]
    assert set(fence) == {"`"} and len(fence) >= 3, "no opening fence: %r" % fence
    assert len(fence) > max(len(run) for run in re.findall(r"`+", rules)), (
        "the opening fence is no longer than a run inside the ruleset, so the block closes "
        "on that run and the rest renders as markdown: %r" % fence)
    assert lines[-1] == fence, "the block does not end on its own fence: %r" % lines[-1]
    assert [ln for ln in lines if ln == fence] == [fence, fence], (
        "a third fence line - one of them is dangling")
    assert "\n".join(lines[1:-1]).rstrip("\n") == rules.rstrip("\n"), (
        "the ruleset did not survive into the fence intact")


def test_the_truncation_note_is_written_outside_the_fence_not_inside_it():
    """Inside the fence the note's backticks render literally and it reads as one more line
    of the ruleset it is describing - the report's own voice, dressed as the payload."""
    big = 'rule Big {\n  strings:\n    $a = "%s"\n  condition:\n    $a\n}\n' % ("x" * 5000)
    res = _run(b64=_b64(big))
    o = res.outputs
    lines = res.readable_output.split("#### Decoded text\n", 1)[1].splitlines()

    fence = lines[0]
    closing = max(i for i, ln in enumerate(lines) if ln == fence)
    notes = [i for i, ln in enumerate(lines) if "`Yara.RulesDecoded.rules` holds" in ln]
    assert len(notes) == 1, lines
    assert notes[0] > closing, "the note is inside the code fence: %r" % lines[notes[0]]
    assert "showing %s of the %s characters" % (
        format(D._MD_RULES_CHARS, ",d"), format(len(o["rules"]), ",d")) in lines[notes[0]]
    assert "\n".join(lines[1:closing]) == o["rules"][:D._MD_RULES_CHARS], (
        "the fence holds something other than the first %d characters" % D._MD_RULES_CHARS)


# ------------------------------------------------------ the yml contract is not fiction

def _scenario_outputs():
    outs = [_run(b64=_b64(PLAIN), expected_hash="deadbeefcafe").outputs,
            _run(b64=SCENARIOS["pdf"]["b64"], validate="false").outputs]
    outs += [_run(**args).outputs for args in SCENARIOS.values()]
    return outs


def test_every_declared_output_is_actually_produced():
    """Union across scenarios rather than one pass: no single run populates rule_names and
    errors at once, and requiring that would only prove something about a contrived payload.
    A declared object key must be present on EVERY entry of its list wherever the list is
    populated - a key some entries carry is a transformer that matches some of the time,
    which is worse than one that never does."""
    scenarios = _scenario_outputs()
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
    for o in _scenario_outputs():
        undeclared = sorted(set(o) - declared)
        assert not undeclared, (
            "produced but never declared in the yml: %s" % undeclared)
        for entry in o["errors"]:
            leaves = {"errors.%s" % k for k in entry}
            assert not leaves - declared, (
                "an error record key is not declared: %s" % sorted(leaves - declared))
