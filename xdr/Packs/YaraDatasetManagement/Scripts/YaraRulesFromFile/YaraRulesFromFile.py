"""YaraRulesFromFile - turn an operator-uploaded rules file into the scanner's yarafile input.

An analyst opens an issue and attaches their YARA rules. This reads that file, VALIDATES it,
and returns the base64 the Action Center scanner expects, plus the ruleset hash the scan will
be filed under.

WHY IT VALIDATES HARDER THAN THE SCANNER DOES. decode_yara_rules on the endpoint only checks
that the input base64-decodes and contains the word `rule`. That permissiveness is right there
- it runs per host, and rejecting late costs one host. This runs ONCE, before dispatch, so a
pack that cannot possibly compile should be stopped here rather than compile-failing on every
host in the wave. The checks below are the ones that can be made without libyara, which is not
in this automation's docker image: structure, balance, encoding, size.

It cannot prove a pack compiles. Two things it deliberately does not catch:
  - rules valid on one agent and not another (base64/base64wide modifiers, pe.* fields) - that
    is per-OS and belongs to the canary dispatch, not to a text check
  - semantic errors inside a condition
`failed_rules` on the scan's lifecycle row remains the authority on what actually compiled.

NO CREDENTIALS. This is the one pack automation that touches no tenant API - it reads a War
Room file and returns text. A credential block here would be a fourth place to rotate keys
for no reason.
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


# A YARA regex literal - $x = /pattern/modifiers - can contain braces that are not
# structural: a quantifier like {2,3}, or an escaped \{. They never span lines, so removing
# them before counting is exact rather than heuristic.
_REGEX_LITERAL_RE = re.compile(r"=\s*/(?:\\.|[^/\\\n])*/[a-z]*")


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


def read_entry(entry_id):
    """War Room entry id -> (bytes, filename). Raises with an actionable message."""
    res = demisto.getFilePath(entry_id)
    if not res or not res.get("path"):
        raise ValueError("Entry %s is not a file entry, or the file is no longer available."
                         % entry_id)
    with open(res["path"], "rb") as fh:
        return fh.read(), res.get("name") or str(entry_id)


def _from_file_context():
    """File.EntryID - where a file uploaded to the War Room lands in context.

    `File` is a dict when one file is present and a list once there are several, so both
    shapes have to be handled. Newest last, matching the attachment convention below.
    """
    try:
        ctx = demisto.context() or {}
    except Exception:
        return None
    f = ctx.get("File")
    if isinstance(f, dict):
        f = [f]
    if not isinstance(f, list):
        return None
    for item in reversed(f):
        if isinstance(item, dict):
            eid = item.get("EntryID") or item.get("entryID") or item.get("entryId")
            if eid:
                return eid
    return None


def _from_war_room():
    """Newest file entry in the War Room.

    Mirrors CommonScripts/UnzipFile: enumerate with getEntries and take `entry["ID"]` of
    entries that carry a `File` name. This is the case the incident-attachment lookup below
    misses entirely - a file uploaded straight into the War Room is never an attachment.
    """
    try:
        entries = demisto.executeCommand("getEntries", {}) or []
    except Exception:
        return None
    if not isinstance(entries, list):
        return None
    found = None
    for entry in entries:
        if isinstance(entry, dict) and entry.get("File") and entry.get("ID"):
            found = entry["ID"]          # keep going; the last one wins
    return found


def _from_attachments():
    """The newest file attached to this incident, or None.

    Lets an analyst attach rules at issue creation without hunting for an entry id. Newest
    wins so re-uploading a corrected file supersedes the broken one without deleting it.
    """
    try:
        inc = demisto.incident() or {}
    except Exception:
        return None
    atts = inc.get("attachment") or []
    if not isinstance(atts, list) or not atts:
        return None
    last = atts[-1]
    return last.get("entryID") or last.get("EntryID") or last.get("entry_id")


def find_rules_entry_id():
    """Locate the uploaded rules file without the analyst hunting for an entry id.

    Three sources, most-specific first. Only the third was checked before, which meant a
    file uploaded to the War Room - the ordinary way - reported "no rules file found".
    """
    for probe in (_from_file_context, _from_war_room, _from_attachments):
        eid = probe()
        if eid:
            return eid
    return None


# Kept so anything calling the old name keeps working.
find_attachment_entry_id = _from_attachments


def main():
    args = demisto.args()
    # `entryID`, the name every Cortex content script uses (CommonScripts/ReadFile,
    # CommonScripts/UnzipFile). One spelling only - two would just be clutter in the
    # argument list, and nothing had consumed the old one.
    entry_id = (args.get("entryID") or "").strip() or None
    mb = args.get("max_bytes")
    try:
        max_bytes = int(mb) if mb not in (None, "") else DEFAULT_MAX_BYTES
    except (TypeError, ValueError):
        return_error("YaraRulesFromFile: max_bytes must be a whole number (%r given)." % mb)
        return

    if not entry_id:
        entry_id = find_rules_entry_id()
    if not entry_id:
        return_error(
            "YaraRulesFromFile: no rules file found. Attach the .yar/.txt file to this issue, "
            "or pass entry_id with the War Room entry of the uploaded file.")
        return

    try:
        raw, filename = read_entry(entry_id)
    except Exception as ex:
        return_error("YaraRulesFromFile: could not read entry %s - %s" % (entry_id, ex))
        return

    result = validate_rules(raw, max_bytes=max_bytes)
    result["entry_id"] = entry_id
    result["filename"] = filename

    if result["valid"]:
        lines = ["Rules accepted from **%s**." % filename,
                 "%d rule(s): %s" % (result["rule_count"],
                                     ", ".join(result["rule_names"][:12])
                                     + (" ..." if result["rule_count"] > 12 else "")),
                 "ruleset hash: `%s` - this scan's results consolidate into "
                 "`yara_scanner_summary_v4_rules_%s` and "
                 "`yara_scanner_full_v4_rules_%s`."
                 % (result["rule_hash"], result["rule_hash"], result["rule_hash"]),
                 "%d bytes, base64 length %d." % (result["size_bytes"], len(result["b64"]))]
    else:
        lines = ["Rules REJECTED from **%s** - nothing was dispatched." % filename, ""]
        lines += ["  - %s" % e for e in result["errors"]]
        lines += ["", "This check runs before dispatch so a pack that cannot compile never "
                      "reaches the fleet. It cannot prove a pack compiles: rules valid on one "
                      "agent may still fail on another, which the scan's own `failed_rules` "
                      "reports."]

    # List-valued context is APPENDED to across calls in one investigation, so a second
    # upload in the same issue would otherwise show both files' rule names merged.
    demisto.executeCommand("DeleteContext", {"key": "Yara.Rules"})
    return_results(CommandResults(readable_output="\n".join(lines),
                                  outputs_prefix="Yara.Rules",
                                  outputs=result, raw_response=result))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
