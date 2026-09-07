"""YaraRulesDecode - turn the scanner's yarafile base64 back into readable YARA rules.

The inverse of YaraRulesFromFile, and the reason it exists is verification, not convenience.
A consolidated dataset is named after a ruleset hash - yara_scanner_full_v4_rules_<hash> - so
when an analyst asks "which rules produced these matches?", the hash alone cannot answer it:
it is one-way. What this does is close the loop from the other end. Give it the base64 that
was dispatched and it returns the rules text AND recomputes the hash, so a match against
`expected_hash` is proof that this text is what that dataset was named for.

THREE THINGS IT IS FOR
  1. Verification. Confirm the encode step produced exactly what was intended before dispatch.
  2. Forensics. Recover the readable ruleset behind an existing dataset or scan record.
  3. Hand-off. An operator handed a base64 blob can read it without a local toolchain.

STRICT ABOUT THE ALPHABET, TOLERANT ABOUT LAYOUT. Whitespace and missing padding are artifacts
of moving a blob through context and copy-paste, so both are repaired. Characters outside the
base64 alphabet are NOT: Python's decoder discards them by default, which turns a corrupted
payload into plausible garbage rather than an error. Corruption has to be loud here, because
the whole point of this automation is to be trusted as evidence.

THE ROUND TRIP IS NORMALISING, NOT BYTE-EXACT. YaraRulesFromFile strips a UTF-8 BOM before
hashing, so decoding what it produced returns the text WITHOUT the BOM even if the uploaded
file had one. That is the intended contract: the hash, the dispatched bytes and this output
all agree with each other, and all of them differ from a BOM-carrying original by that BOM.

NO CREDENTIALS. Like YaraRulesFromFile, this touches no tenant API - it decodes text.

The validation helpers below are lifted VERBATIM from YaraRulesFromFile and pinned there by
a drift test. If the two disagreed about what a valid ruleset is, this automation could
declare a dispatched pack invalid, or bless one the gate would have refused.
"""
import base64
import hashlib
import re

# A rules file bigger than this is a mistake, not a ruleset. The scanner's own ceiling is
# 50 MB of BASE64, which is far past anything a human uploads to an issue; refusing early
# keeps a stray disk image out of the War Room round trip.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024

_RULE_RE = re.compile(r"(?m)^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+([A-Za-z_]\w*)")


_CONDITION_RE = re.compile(r"(?m)^[ \t]*condition[ \t]*:")


# Printable ASCII plus tab/newline/CR, and the common Latin-1 range a comment might carry.
_TEXTY = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D} | set(range(0xA0, 0x100))


# A YARA regex literal - $x = /pattern/modifiers - can contain braces that are not
# structural: a quantifier like {2,3}, or an escaped \{. They never span lines, so removing
# them before counting is exact rather than heuristic.
_REGEX_LITERAL_RE = re.compile(r"=\s*/(?:\\.|[^/\\\n])*/[a-z]*")


def _decode_bytes(raw):
    """Bytes -> text, or None if this is not a text file at all."""
    if isinstance(raw, str):
        return raw
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return None


def _looks_binary(text):
    """True if the content is not plausibly a text rules file.

    NUL is decisive - no text editor emits it. Beyond that, a small fraction of exotic bytes
    is normal (a UTF-8 comment), so only a heavy concentration counts.
    """
    if "\x00" in text:
        return True
    sample = text[:4096]
    if not sample:
        return False
    odd = sum(1 for ch in sample if ord(ch) not in _TEXTY)
    return (odd / float(len(sample))) > 0.10


def _brace_balance(text):
    """Net brace depth, ignoring braces inside strings and // or /* */ comments.

    A hex string like { 4D 5A } counts as a normal brace pair and balances itself, so it needs
    no special case. Quoted strings do: a rule containing "}" would otherwise read as a close.
    """
    text = _REGEX_LITERAL_RE.sub("= REGEX", text)
    depth, i, n = 0, 0, len(text)
    in_str = in_line_comment = in_block_comment = False
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_str:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            i += 1
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return depth
        i += 1
    return depth


def validate_rules(raw, max_bytes=DEFAULT_MAX_BYTES):
    """Validate a rules file and return everything the playbook needs.

    Always returns a dict - never raises - so a playbook can branch on `valid` and show
    `errors` to the analyst who uploaded the file. Every error names what to fix.
    """
    out = {"valid": False, "errors": [], "rule_names": [], "rule_count": 0,
           "b64": "", "rule_hash": "", "size_bytes": 0}

    text = _decode_bytes(raw)
    if text is not None:
        # A UTF-8 BOM is what Notepad and most Windows editors write by default. It sits
        # immediately before the first `rule`, so the declaration scan misses it and a
        # perfectly good file is rejected as "no rules". libyara would not accept it either,
        # so stripping it is a fix, not a workaround.
        text = text.lstrip("\ufeff")
    if text is None:
        out["errors"].append("File is not text: it could not be decoded as UTF-8 or Latin-1. "
                             "Upload the rules as a plain .yar/.yara/.txt file.")
        return out

    out["size_bytes"] = len(text.encode("utf-8", "replace"))
    if not text.strip():
        out["errors"].append("File is empty - it contains no rules.")
        return out
    if max_bytes and out["size_bytes"] > max_bytes:
        out["errors"].append("File is too large: %d bytes against a %d byte limit."
                             % (out["size_bytes"], max_bytes))
        return out

    # Named before the generic binary check so the operator gets the useful message. A PDF is
    # the likeliest wrong upload when the ask is "attach your rules".
    if text.lstrip()[:5] == "%PDF-":
        out["errors"].append("File is a PDF. Only plain-text YARA rules are supported - "
                             "export or copy the rules into a .yar/.txt file and re-upload.")
        return out
    if _looks_binary(text):
        out["errors"].append("File looks binary, not text. Only plain-text YARA rules are "
                             "supported.")
        return out

    names = _RULE_RE.findall(text)
    if not names:
        out["errors"].append("No YARA rule declarations found. A rules file needs at least "
                             "one `rule <Name> { ... }` block.")
        return out
    out["rule_names"] = names
    out["rule_count"] = len(names)

    depth = _brace_balance(text)
    if depth != 0:
        out["errors"].append(
            "Unbalanced braces (%s). Every `rule { ... }` block must be closed."
            % ("%d unclosed" % depth if depth > 0 else "%d unexpected closing" % -depth))
        return out

    # YARA requires a condition per rule. Counting is enough and avoids parsing rule bodies:
    # fewer conditions than rules means at least one rule cannot compile.
    conditions = len(_CONDITION_RE.findall(text))
    if conditions < len(names):
        out["errors"].append(
            "%d rule(s) but only %d `condition:` section(s). Every YARA rule requires a "
            "condition." % (len(names), conditions))
        return out

    # sha256 of the DECODED text, matching the scanner exactly (xdr_yara_scanner.py:2849), so
    # the hash reported here is the one the consolidated datasets get named after.
    out["rule_hash"] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    out["b64"] = base64.b64encode(text.encode("utf-8")).decode("ascii")
    out["valid"] = True
    return out



# Padding is derivable and whitespace is an artifact of moving a blob through context, so both
# are repaired. The alphabet is not repairable: b64decode DISCARDS stray characters unless
# validate=True, which is how corruption becomes plausible garbage instead of an error.
_B64_ALPHABET_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_URLSAFE_RE = re.compile(r"[-_]")


# ---------------------------------------------------------------------------------------
# THE `errors` LIST IS CONTEXT, NOT PROSE.
#
# Every entry is an OBJECT with a fixed key set, and `reason` comes from the closed
# vocabulary below. A playbook wanting to tell "the operator uploaded a PDF" from "the
# payload is 3 MB" from "someone pasted URL-safe base64" from "the braces do not balance"
# previously had nothing to match on but an English sentence written for a human: reword one
# for clarity and every filter downstream stops matching, silently and with no error
# anywhere. Fourteen distinct conditions all arrived as one untyped string.
#
# EVERY RECORD CARRIES EVERY KEY, even where one does not apply, because a transformer
# filtering on a sometimes-absent key matches nothing and reports no error - a silently empty
# branch, which is the worst kind to debug.
#
# THE VALIDATOR'S SENTENCES ARE CLASSIFIED, NOT REWRITTEN. validate_rules above is a verbatim
# copy of YaraRulesFromFile's and is pinned to it byte-for-byte (AST, docstring included) by
# tests/test_rules_decode.py, so it cannot be given reason codes here without drifting from
# the very function this automation exists to agree with. The markers below are matched
# against those pinned sentences instead, and the test drives every one of its refusal
# branches through decode_rules to prove that none of them lands as `unclassified`.
#
# A HASH MISMATCH IS NOT IN HERE. It is a finding about provenance, not about the rules, and
# folding it into `errors` would break the one invariant a playbook can rely on - ok is
# exactly `not errors`. It is reported by `hash_matches` instead, which has the third state
# `errors` could not express: not checked.
# ---------------------------------------------------------------------------------------

ERROR_REASONS = {
    "no_input":
        "nothing was passed to decode - neither b64 nor an entry_id that could be read",
    "urlsafe_b64":
        "the payload uses the URL-safe alphabet (- and _); the scanner's yarafile input is "
        "standard base64, so this was encoded by something else",
    "bad_alphabet":
        "the payload carries characters outside the base64 alphabet - typically quotes or "
        "line markers picked up when it was pasted out of a document",
    "invalid_b64":
        "the payload is base64-shaped but the decoder refused it - truncated or corrupted "
        "in transit",
    "not_text":
        "the decoded bytes are not text in UTF-8, UTF-8-with-BOM or Latin-1",
    "empty": "the decoded text is empty or whitespace only",
    "too_large": "the decoded text is larger than the max_bytes ceiling",
    "pdf": "the decoded text is a PDF, not a rules file",
    "binary": "the decoded text is not plausibly text at all",
    "no_rules": "the text carries no `rule <Name> { ... }` declaration",
    "unbalanced_braces":
        "the braces do not balance, so a rule block is left unclosed or closed twice",
    "missing_conditions":
        "fewer `condition:` sections than rules - at least one rule cannot compile",
    "unclassified":
        "a refusal whose sentence this file does not recognise. The shared validator's "
        "wording drifted without this vocabulary being updated - a bug here, not a state of "
        "the payload",
}

# Where the payload was refused. Not derivable from the reason: not_text arises at both.
ERROR_STAGES = ("decode", "validate")


def _error_record(reason, detail, stage, observed=None, limit=None):
    """One `errors` entry.

    `stage` is "decode" for the base64-and-text step or "validate" for the structural gate,
    which tells an operator whether to re-copy the payload or fix the ruleset - and is not
    derivable from `reason`, since not_text can come from either. `observed` and `limit` are
    the two numbers a quantitative refusal compared, so a caller never has to read them back
    out of the sentence; both are None where the reason is not a comparison.
    """
    return {"reason": reason, "detail": str(detail), "stage": stage,
            "observed": observed, "limit": limit}


# Matched against validate_rules' sentences, which are pinned byte-for-byte to the encoder's
# copy. First match wins, so the markers only have to be mutually distinctive.
_VALIDATION_MARKERS = (
    ("File is not text:", "not_text"),
    ("File is empty", "empty"),
    ("File is too large:", "too_large"),
    ("File is a PDF", "pdf"),
    ("File looks binary", "binary"),
    ("No YARA rule declarations found", "no_rules"),
    ("Unbalanced braces", "unbalanced_braces"),
    ("`condition:` section(s)", "missing_conditions"),
)


def _classify_validation_error(sentence):
    """A pinned validator sentence -> a reason code from ERROR_REASONS."""
    for marker, reason in _VALIDATION_MARKERS:
        if marker in str(sentence):
            return reason
    return "unclassified"


def _validation_records(errors, text, rule_count, size_bytes, max_bytes):
    """validate_rules' sentences as records.

    The operands are RECOMPUTED rather than parsed back out of the prose: _brace_balance and
    _CONDITION_RE are the same expressions that produced the sentence, so the numbers on the
    record cannot disagree with the sentence beside them, and no regex has to be kept in step
    with a message it does not own. Both scans cost a single pass over a file that has
    already been refused.
    """
    out = []
    for sentence in errors:
        reason = _classify_validation_error(sentence)
        observed = limit = None
        if reason == "too_large":
            observed, limit = size_bytes, max_bytes
        elif reason == "unbalanced_braces" and text:
            # Signed, exactly as the sentence reads it: positive is unclosed, negative is an
            # unexpected close. The limit is the balance every ruleset must reach.
            observed, limit = _brace_balance(text), 0
        elif reason == "missing_conditions" and text:
            observed, limit = len(_CONDITION_RE.findall(text)), rule_count
        out.append(_error_record(reason, sentence, "validate", observed, limit))
    return out


def decode_b64(text):
    """base64 -> (bytes, error record or None). Never raises."""
    s = re.sub(r"\s+", "", str(text or ""))
    if not s:
        return None, _error_record(
            "no_input",
            "No base64 input given - pass b64, or entry_id of a file containing it.",
            "decode")
    if _URLSAFE_RE.search(s):
        return None, _error_record(
            "urlsafe_b64",
            "Input looks like URL-safe base64 (it contains - or _). The scanner's yarafile "
            "input is standard base64; re-encode with the standard alphabet.",
            "decode")
    if len(s) % 4:
        s += "=" * (4 - len(s) % 4)
    if not _B64_ALPHABET_RE.match(s):
        return None, _error_record(
            "bad_alphabet",
            "Input is not base64: it contains characters outside the base64 alphabet. If "
            "this was pasted from a document, it may have picked up quotes or line markers.",
            "decode")
    try:
        return base64.b64decode(s, validate=True), None
    except Exception as ex:
        return None, _error_record(
            "invalid_b64", "Input is not valid base64: %s" % str(ex)[:120], "decode")


# How much of a REFUSED payload travels in context. A failing payload is shown so the
# operator can see what it actually was, but it is not carried whole: the ceiling that
# refused it may be megabytes. `rules_truncated` says when this bit, because size_bytes is
# the size of the WHOLE decoded text and would otherwise disagree with len(rules) for no
# stated reason.
_FAILED_RULES_CHARS = 4000


def decode_rules(b64_text, expected_hash="", validate=True, max_bytes=DEFAULT_MAX_BYTES):
    """Decode and, unless told otherwise, hold the result to the encoder's own standard."""
    out = {"ok": False, "errors": [], "rules": "", "rules_truncated": False, "rule_hash": "",
           "rule_names": [], "rule_count": 0, "size_bytes": 0,
           "expected_hash": str(expected_hash or "").strip(), "hash_matches": None,
           "validated": bool(validate),
           # The ceiling that was actually APPLIED, not the argument as passed. 0 is the
           # ABSENCE of a ceiling, never a 0-byte one: with validate=false no gate runs at
           # all, and a falsy max_bytes short-circuits validate_rules' `if max_bytes and ...`
           # so the size check never happens either. Reporting a ceiling that never ran would
           # be a claim, which is why the renderer branches on this being truthy rather than
           # on `validated` alone. `validated` tells the two zeroes apart.
           "max_bytes": int(max_bytes or 0) if validate else 0}

    raw, err = decode_b64(b64_text)
    if err:
        out["errors"].append(err)
        return out

    if not validate:
        # Still decode to text so an operator can SEE a payload the gate would refuse - that
        # is exactly the case where reading it matters most.
        text = _decode_bytes(raw)
        if text is None:
            out["errors"].append(_error_record(
                "not_text", "Decoded bytes are not text in any supported encoding.",
                "decode"))
            return out
        text = text.lstrip("\ufeff")
        out["rules"] = text
        out["size_bytes"] = len(text.encode("utf-8", "replace"))
        out["rule_hash"] = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        out["ok"] = True
    else:
        res = validate_rules(raw, max_bytes=max_bytes)
        out["rule_names"] = res["rule_names"]
        out["rule_count"] = res["rule_count"]
        out["size_bytes"] = res["size_bytes"]
        out["rule_hash"] = res["rule_hash"]
        out["ok"] = res["valid"]
        text = _decode_bytes(raw)
        text = (text or "").lstrip("\ufeff") if text is not None else None
        out["errors"] = _validation_records(res["errors"], text, res["rule_count"],
                                            res["size_bytes"], out["max_bytes"])
        if res["valid"]:
            out["rules"] = text or ""
        else:
            # Show what was decoded even on failure - "it decoded to a PDF" is the answer.
            full = text or ""
            out["rules"] = full[:_FAILED_RULES_CHARS]
            out["rules_truncated"] = len(full) > _FAILED_RULES_CHARS

    # Compared AFTER decoding, and it never gates `ok`: a mismatch is a real finding worth
    # reporting on its own, and conflating it with "this is not valid YARA" hides which of
    # the two actually went wrong.
    if out["expected_hash"] and out["rule_hash"]:
        out["hash_matches"] = (out["rule_hash"].lower() == out["expected_hash"].lower())
    return out


_MD_ROW_CAP = 50


def _n(v):
    """Thousands-separated. The numbers this reports run to six figures.

    Integral values print as integers, floats included: the settings arrive as
    float(args.get(...)), and "900.0" in a table reads as a typo rather than a default.

    A NON-integral float keeps its fraction. The previous version went through int(), which
    silently truncated - a quiet_secs of 900.5 printed as 900 while the context carried 900.5,
    so the report and the context stated different numbers. That is the one disagreement this
    renderer exists to make impossible, and it was being introduced by the formatter itself.
    """
    try:
        f = float(v)
    except (TypeError, ValueError):
        return str(v)
    return format(int(f), ",d") if f.is_integer() else format(f, ",g")


def _md_table(headers, rows):
    """A markdown table, or "" when there is nothing to put in it. Cells are escaped: rule
    names and hostnames reach here from a ruleset and from an endpoint, and a single pipe in
    either would silently shear a column off every row below it."""
    if not rows:
        return ""

    def cell(v):
        return str("" if v is None else v).replace("|", "\\|").replace("\n", " ")

    out = ["| " + " | ".join(cell(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join(cell(v) for v in r) + " |")
    return "\n".join(out)


def _md_capped(headers, rows, context_key):
    """_md_table, truncated. The context keeps every entry, so a 200-host pass cannot push the
    counts off the top of the War Room - the same trade YaraReport makes for the scan log."""
    body = _md_table(headers, rows[:_MD_ROW_CAP])
    if len(rows) > _MD_ROW_CAP:
        body += ("\n\n_... and %s more - the full list is in `%s`._"
                 % (_n(len(rows) - _MD_ROW_CAP), context_key))
    return body


# How much of the decoded text the War Room shows. Display only - the context keeps whatever
# `rules` holds, and the report says which it is showing rather than leaving two different
# amounts of the same text under the same name.
_MD_RULES_CHARS = 3000


def _fenced(body):
    """`body` as a fenced code block, as [open, body, close].

    The fence is one backtick longer than the longest run in the text. A ruleset is arbitrary
    operator-supplied content and can carry backticks - in a comment, or because it was pasted
    out of a markdown document - and a fenced block ends at the first line whose fence is at
    least as long as the opening one. With a bare ``` the rest of the ruleset then renders as
    prose, with a stray fence dangling after it, and nothing says so: the operator reads a
    War Room entry that is quietly not the payload. Fencing wider is the CommonMark answer and
    costs nothing when there are no backticks at all.
    """
    longest = max((len(run) for run in re.findall(r"`+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence, body, fence]


def render_decode_markdown(result):
    """The War Room report for one decode, rendered from the result dict and nothing else.

    Every number here is read from `result`, so the table an operator reads and the context a
    playbook branches on cannot state different things. The list is rendered as a table
    rather than by concatenating its entries into lines - that older shape (`out += ["  " +
    s for s in items]`) raises TypeError the moment an entry is an object, which is exactly
    what every entry is now.
    """
    ok = bool(result["ok"])
    if ok and result["validated"]:
        lede = ("Decoded, and it passed the same structural gate YaraRulesFromFile applies "
                "before dispatch.")
    elif ok:
        lede = ("Decoded. The structural gate was SKIPPED (validate=false), so `ok` here "
                "means this is text - not that it is a usable ruleset.")
    else:
        lede = ("This payload could not be turned into usable YARA rules. Every row under "
                "Problems names what to fix.")
    out = ["### YARA rules decode - %s" % ("DECODED" if ok else "REFUSED"), "_%s_" % lede, ""]

    if result["hash_matches"] is True:
        hash_check = "MATCHES - this text is what that scan dispatched"
    elif result["hash_matches"] is False:
        hash_check = ("MISMATCH - this text hashes to `%s`, not the expected `%s`. The "
                      "payload is not the ruleset it was said to be."
                      % (result["rule_hash"], result["expected_hash"]))
    elif result["expected_hash"]:
        # hash_matches has ONE null state and two ways to reach it. Saying "no expected_hash
        # was given" here would contradict the Expected hash row directly above, and would
        # tell an operator who did supply one that they had not.
        hash_check = ("NOT CHECKED - `%s` was given, but nothing decoded to a hash to "
                      "compare it against" % result["expected_hash"])
    else:
        hash_check = "not requested - no expected_hash was given"

    # Derived from the same condition validate_rules applies (`if max_bytes and ...`), not
    # from `validated`: a falsy ceiling means the size check never ran, and calling that "a 0
    # byte ceiling" states a comparison that never happened.
    if not result["validated"]:
        validation = "SKIPPED - validate=false"
    elif result["max_bytes"]:
        validation = "applied, against a %s byte ceiling" % _n(result["max_bytes"])
    else:
        validation = ("applied, with NO size ceiling - max_bytes=%s disables the size "
                      "check, so nothing was compared against a limit"
                      % _n(result["max_bytes"]))

    facts = [
        ("Result", "decoded" if ok else "refused"),
        ("Decoded size", "%s bytes" % _n(result["size_bytes"])),
        ("Rules found", _n(result["rule_count"])),
        ("Ruleset hash", ("`%s`" % result["rule_hash"]) if result["rule_hash"] else "-"),
        ("Expected hash", ("`%s`" % result["expected_hash"]) if result["expected_hash"]
                          else "not given"),
        ("Hash check", hash_check),
        ("Structural validation", validation),
        ("Problems", _n(len(result["errors"]))),
        ("Rules text in context", ("truncated to the first %s characters - the payload "
                                   "failed validation" % _n(_FAILED_RULES_CHARS))
                                  if result["rules_truncated"] else "complete"),
    ]
    out.append(_md_table(["", ""], [("**%s**" % k, v) for k, v in facts]))

    if result["errors"]:
        out += ["", "#### Problems",
                _md_capped(["Stage", "Reason", "Observed", "Limit", "Detail"],
                           [(e["stage"], "`%s`" % e["reason"],
                             "-" if e["observed"] is None else _n(e["observed"]),
                             "-" if e["limit"] is None else _n(e["limit"]), e["detail"])
                            for e in result["errors"]],
                           "Yara.RulesDecoded.errors")]

    if result["rule_names"]:
        out += ["", "#### Rules decoded",
                _md_capped(["#", "Rule"],
                           [(i + 1, n) for i, n in enumerate(result["rule_names"])],
                           "Yara.RulesDecoded.rule_names")]

    if result["rules"]:
        body = result["rules"]
        note = ""
        if len(body) > _MD_RULES_CHARS:
            # Outside the fence, not in it: inside, its backticks render literally and the
            # note reads as one more line of the ruleset it is describing.
            note = ("_... (showing %s of the %s characters `Yara.RulesDecoded.rules` holds)_"
                    % (_n(_MD_RULES_CHARS), _n(len(body))))
            body = body[:_MD_RULES_CHARS]
        out += ["", "#### Decoded text"] + _fenced(body)
        if note:
            out.append(note)
    return "\n".join(out)


def main():
    args = demisto.args()
    b64_text = args.get("b64") or ""
    entry_id = (args.get("entry_id") or "").strip()
    expected = (args.get("expected_hash") or "").strip()

    if not b64_text and entry_id:
        try:
            res = demisto.getFilePath(entry_id)
            if not res or not res.get("path"):
                return_error("YaraRulesDecode: entry %s is not a file entry." % entry_id)
                return
            with open(res["path"], "rb") as fh:
                b64_text = fh.read().decode("utf-8", "replace")
        except Exception as ex:
            return_error("YaraRulesDecode: could not read entry %s - %s" % (entry_id, ex))
            return
    if not b64_text:
        return_error("YaraRulesDecode: nothing to decode. Pass b64 with the base64 payload, "
                     "or entry_id of a file that contains it.")
        return

    try:
        validate = argToBoolean(args.get("validate", "true"))
    except (ValueError, TypeError):
        return_error("YaraRulesDecode: validate must be true or false (%r given)."
                     % args.get("validate"))
        return
    try:
        as_file = argToBoolean(args.get("as_file", "false"))
    except (ValueError, TypeError):
        return_error("YaraRulesDecode: as_file must be true or false (%r given)."
                     % args.get("as_file"))
        return
    mb = args.get("max_bytes")
    try:
        max_bytes = int(mb) if mb not in (None, "") else DEFAULT_MAX_BYTES
    except (TypeError, ValueError):
        return_error("YaraRulesDecode: max_bytes must be a whole number (%r given)." % mb)
        return
    # Refused rather than passed through, because neither value is a ceiling. 0 SILENTLY
    # DISABLES the size check (validate_rules guards with `if max_bytes and ...`), so the
    # payload is judged against no limit at all while the argument reads like a strict one;
    # a negative value is worse than useless - every payload, a perfectly good ruleset
    # included, is refused as too_large against a limit no file can be under.
    if max_bytes <= 0:
        return_error("YaraRulesDecode: max_bytes must be a positive number of bytes (%r "
                     "given). 0 disables the size check rather than setting a ceiling, and "
                     "a negative value refuses every payload. Omit max_bytes for the "
                     "%d byte default, or pass validate=false to skip the gate entirely."
                     % (mb, DEFAULT_MAX_BYTES))
        return

    result = decode_rules(b64_text, expected_hash=expected, validate=validate,
                          max_bytes=max_bytes)

    results = [CommandResults(readable_output=render_decode_markdown(result),
                              outputs_prefix="Yara.RulesDecoded",
                              outputs=result, raw_response=result)]
    if as_file and result["rules"]:
        try:
            results.append(fileResult("decoded_rules_%s.yar" % (result["rule_hash"] or "x"),
                                      result["rules"]))
        except Exception as ex:
            demisto.debug("YaraRulesDecode: file output unavailable - %s" % ex)

    # List-valued context is APPENDED to across calls in one investigation, so a second
    # decode would otherwise merge both payloads' rule names.
    demisto.executeCommand("DeleteContext", {"key": "Yara.RulesDecoded"})
    return_results(results)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
