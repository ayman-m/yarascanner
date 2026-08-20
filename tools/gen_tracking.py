#!/usr/bin/env python3
r"""Regenerate `<edition>/docs/TEST_TRACKING.md` from the files that actually hold the facts.

WHY THIS EXISTS
===============

Both trackers were hand-maintained, and both drifted in the same way for the same
reason: the body of the table was edited row by row while the Progress block at the
top was retyped from memory. The results speak for themselves.

  * `xdr/docs/TEST_TRACKING.md` says **0 of 444 executed** and shows `0 | 0 | 0` for
    every round -- while its own body carries 66 `pass` and 68 `blocked` rows for
    Round 1. The header contradicts the table three lines below it.
  * `xsiam/docs/TEST_TRACKING.md` says **276 of 276 executed**, which reads like full
    coverage. Its body has 297 rows. The 21 `not_covered` rows are not in the header
    at all -- not as a row, not as a column, not as a footnote -- so the denominator
    quietly stopped meaning "every catalogued capability" and nobody noticed.

Neither number was wrong when it was typed. They went wrong afterwards, because
nothing recomputed them. So the contract here is narrow and blunt:

    Every number in the output is counted from the rows this same run just built,
    and the header accounts for all of them -- `not_covered` included.

There is a second, subtler failure this file is built to resist: silent skipping.
A parser that shrugs at a row it cannot read produces a *shorter* tracker that still
looks plausible, and that is indistinguishable from a capability being deliberately
retired. So every table we treat as a data source is parsed strictly: an unreadable
row raises and the run dies with a file:line. Nothing is skipped quietly.

WHERE THE FACTS LIVE (and why each source is the one used)
==========================================================

`TEST_PLAN.md` -- THE INVENTORY.
    The only file that structurally encodes `id -> (capability name, round, priority)`.
    Rounds come from the enclosing `# Round N` heading; priority from the first
    non-blank line under the criterion heading. `CAPABILITIES.md` is upstream of the
    names but contains no IDs at all (its only `-\d{3}` matches are the string
    `SHA-256`), so it cannot key anything and is deliberately not read here.
    The plan also carries the `# Not covered` table, which is where the untestable
    capabilities and their reasons live.

`docs/rounds/ROUND<N>_RESULTS.md` -- THE VERDICTS.
    Where a round doc ends with a `## All criteria` table, that table is the primary
    record of what passed: `| ID | Capability | Pri | Status | Evidence |`. XSIAM has
    one in all three round docs (55 + 107 + 114 = 276 verdicts). XDR has none, in any
    round doc, in any revision of any round doc -- which is the root cause of XDR's
    unwritten-back rounds and is reported as a GAP finding on every run.

`TEST_TRACKING.md` itself -- THE CARRY-FORWARD STORE.
    Some fields exist nowhere else and cannot be recomputed:
      * XDR Round 1's 134 verdicts. They were written straight into the tracker in
        the same commit that deleted the only per-ID table its results doc ever had.
        The tracker *is* the primary record for them; there is no upstream to re-read.
      * The `Notes` column, in both editions. Round docs have no Notes column, so the
        14 XSIAM caveats ("probe only: absence does not prove the branch is dead", ...)
        and every `not_covered` reason as rendered here survive only in this file.
      * `Priority` for `not_covered` rows. The plan's not-covered table has no priority
        column; the tracker is the sole source for those 23 (XDR) and 21 (XSIAM) values.
    Carry-forward is therefore load-bearing, and it has an honest cost: a field that is
    only ever carried forward cannot be *validated* by `--check`, because the check is
    comparing the file against itself. The run says so out loud in its NOTE findings
    rather than letting the green exit code imply more than it proves.

PRECEDENCE, per field, highest first:

    capability  plan  ->  tracker
    round       plan  ->  tracker
    priority    plan  ->  tracker            (not_covered rows: tracker only)
    status      round doc  ->  tracker  ->  not_covered (if in the plan's NC table)  ->  not_run
    evidence    round doc  ->  tracker  ->  em dash
    notes       tracker  ->  em dash

Where a lower-precedence source disagrees with a higher one, the higher one wins AND
the disagreement is printed as a finding. It is never silently absorbed -- an
adjudication nobody can see is just a second, quieter kind of drift.

Round-doc capability text is deliberately NEVER used: those tables hard-slice the name
at 79 characters plus an ellipsis (13 of the 276 XSIAM rows are cut mid-word). It is a
display truncation, not a shorter name.

USAGE
=====

    python3 tools/gen_tracking.py --edition xdr              # rewrite the tracker
    python3 tools/gen_tracking.py --edition xdr --check      # CI gate: diff, don't write
    python3 tools/gen_tracking.py --edition xsiam --stdout   # print, touch nothing

Exit codes: 0 clean · 1 `--check` found a difference (or drift) · 2 a source would not parse.
"""

from __future__ import annotations

import argparse
import dataclasses
import difflib
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------------------
# Vocabulary and layout constants
# --------------------------------------------------------------------------------------

STATUSES = ("not_run", "pass", "fail", "blocked", "not_covered")

# The order rows appear in, in BOTH committed trackers: grouped by ID prefix in this
# fixed sequence, ascending numerically inside each group. It is not derivable from the
# plan -- XSIAM's plan introduces the prefixes in the order TRAV, PERF, LIFE, STOR, DELI,
# RULE (round by round), which is not the tracker's order -- so it is stated here.
# An ID with a prefix outside this tuple is a hard error rather than something quietly
# appended at the end: a new capability family is a decision, not a parsing outcome.
PREFIX_ORDER = ("RULE", "TRAV", "PERF", "STOR", "DELI", "LIFE")

EM_DASH = "—"      # the "no value" placeholder used in every cell of both trackers
ELLIPSIS = "…"     # the truncation marker

# Evidence and notes are clamped so one runaway log line cannot make the table
# unreadable. 200 was not chosen here -- it is the cap already in force in the committed
# XSIAM tracker, recovered by fitting: it is the only limit that reproduces all three of
# the truncated cells (PERF-041 -> 190 chars, TRAV-027 -> 185, TRAV-028 -> 199) from the
# round docs' own 220-char copies. Keeping it means writing back from a round doc is a
# no-op on the 273 rows that already fit, instead of a 276-row reflow.
CELL_LIMIT = 200

ID_RE = re.compile(r"[A-Z]+-\d{3}")
ID_ROW_RE = re.compile(r"^\|\s*`([A-Z]+-\d{3})`\s*\|")
# Census pattern: backticked, and only the prefixes that are real capability families. See
# the CENSUS block in read_tracker for why this is deliberately narrower than ID_RE.
CENSUS_ID_RE = re.compile(r"`((?:%s)-\d{3})`" % "|".join(PREFIX_ORDER))

# Split on UNESCAPED pipes only. Evidence cells quote scanner stdout verbatim, and that
# output is full of `\|` -- "SCAN COMPLETED \| Time: 0:00:07 \| Files: 8003 scanned".
# A plain line.split("|") turns those rows into 7 or 9 cells instead of 5 or 7, and the
# tempting fix (skip rows with the wrong cell count) is precisely the silent skip that
# would drop real verdicts. 7 XSIAM round-doc rows and 8 tracker rows depend on this.
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")

# TEST_PLAN.md structure.
# NOTE the single `#` with an explicit "not `##`" guard: XDR's plan repeats all three
# round titles as H2 headings in its prose intro (lines 34, 55, 85) long before the real
# H1 sections at 181, 1563 and 2650. A parser keyed on `^##? Round` files 444 criteria
# under the wrong rounds and still looks like it worked.
PLAN_H1_ROUND_RE = re.compile(r"^#[ \t]+Round[ \t]+(\d+)\b")
PLAN_H1_NOTCOVERED_RE = re.compile(r"^#[ \t]+Not covered\b")
PLAN_CRITERION_RE = re.compile(r"^###[ \t]+`([A-Z]+-\d{3})`[ \t]+(.+?)[ \t]*$")
# `*supporting*` (XDR) and `***core*** · on \`xsoar\`` (XSIAM) are the same field with
# two renderings; one regex covers both because the trailing decoration is not anchored.
PLAN_PRIORITY_RE = re.compile(r"^\*+(core|supporting|low)\*+")

ROUND_DOC_RE = re.compile(r"^ROUND(\d+)_RESULTS\.md$")
VERDICT_SECTION = "## All criteria"

TRACKER_TABLE_HEADER = "| ID | Capability | Rnd | Pri | Status | Evidence | Notes |"
TRACKER_TABLE_RULE = "|---|---|---|---|---|---|---|"


# --------------------------------------------------------------------------------------
# Editions
# --------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Edition:
    key: str
    preamble: str
    status_render: dict

    def render_status(self, status: str) -> str:
        if status not in self.status_render:
            raise GeneratorBug(f"{self.key}: no rendering defined for status {status!r}")
        return self.status_render[status]


# The preambles are stored verbatim, wrapping and all. They differ between editions only
# in where the sentence breaks ("Regenerated after / each round" vs "Regenerated / after
# each round"), which is meaningless -- but reflowing it would make `--check` report a
# diff on every line of both files and bury the one difference that matters.
_XDR_PREAMBLE = """# XDR Live Test Tracking

Status of every catalogued XDR capability against live endpoints. Regenerated after
each round; `TEST_PLAN.md` holds the criteria themselves.

**Status values:** `not_run` · `pass` · `fail` · `blocked` · `not_covered`
"""

_XSIAM_PREAMBLE = """# XSIAM Live Test Tracking

Status of every catalogued XSIAM capability against live endpoints. Regenerated
after each round; `TEST_PLAN.md` holds the criteria themselves.

**Status values:** `not_run` · `pass` · `fail` · `blocked` · `not_covered`
"""

# Status decoration is per edition and is COPIED, not invented. XSIAM ticks its passes,
# XDR does not; both render not_covered with a leading em dash. `fail` and `blocked` have
# never appeared in the XSIAM tracker, so there is no house style to copy for them -- they
# render bare. Inventing a decoration for an unobserved status would be a fresh source of
# drift the day someone's run finally produces one.
EDITIONS = {
    "xdr": Edition(
        key="xdr",
        preamble=_XDR_PREAMBLE,
        status_render={
            "not_run": "not_run",
            "pass": "pass",
            "fail": "fail",
            "blocked": "blocked",
            "not_covered": f"{EM_DASH} not_covered",
        },
    ),
    "xsiam": Edition(
        key="xsiam",
        preamble=_XSIAM_PREAMBLE,
        status_render={
            "not_run": "not_run",
            "pass": "✅ pass",
            "fail": "fail",
            "blocked": "blocked",
            "not_covered": f"{EM_DASH} not_covered",
        },
    ),
}


# --------------------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------------------

class ParseError(Exception):
    """A source file said something this generator will not guess at.

    Always carries file:line. The whole point is that the operator can open the exact
    line -- a message like "3 rows skipped" is how the drift happened in the first place.
    """

    def __init__(self, path: Path, lineno: int, message: str):
        super().__init__(f"{path}:{lineno}: {message}")


class GeneratorBug(RuntimeError):
    """An internal invariant broke -- e.g. the header arithmetic did not add up.

    A plain `assert` would be wrong here: asserts disappear under `python -O`, and the
    one thing this tool must never do under any flag is emit a total it did not verify.
    """


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Finding:
    kind: str      # DRIFT | GAP | NOTE
    subject: str   # capability ID, round number, or a section name
    message: str

    def line(self) -> str:
        return f"  [{self.kind:<5}] {self.subject:<12} {self.message}"


KIND_ORDER = {"DRIFT": 0, "GAP": 1, "NOTE": 2}


# --------------------------------------------------------------------------------------
# Small parsing helpers
# --------------------------------------------------------------------------------------

def split_cells(line: str) -> list[str]:
    """Return the trimmed cells of one markdown table row (escaped pipes preserved)."""
    parts = CELL_SPLIT_RE.split(line.rstrip("\n"))
    # A well-formed row starts and ends with a pipe, so the first and last fragments are
    # the empty strings on either side of them.
    return [p.strip() for p in parts[1:-1]]


def is_table_furniture(line: str) -> bool:
    """True for a header row or its `|---|---|` rule -- the only non-data pipe lines allowed."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return False
    body = stripped.strip("|").replace(" ", "")
    if set(body) <= set("-:|") and body:
        return True
    return stripped.lstrip("|").lstrip().startswith("ID ")


def clamp_cell(text: str) -> str:
    """Clamp one cell to CELL_LIMIT, cutting at a word boundary and marking the cut."""
    if len(text) <= CELL_LIMIT:
        return text
    cut = text[: CELL_LIMIT - 1]
    space = cut.rfind(" ")
    if space > 0:
        cut = cut[:space]
    cut = cut.rstrip()
    # Never end on a dangling escape: cutting the middle of a `\|` would leave a lone
    # backslash that the next reader's CELL_SPLIT_RE would treat as escaping the closing
    # pipe of the row, silently swallowing the following column.
    trailing_backslashes = len(cut) - len(cut.rstrip("\\"))
    if trailing_backslashes % 2 == 1:
        cut = cut[:-1]
    return cut + ELLIPSIS


def check_writable_cell(value: str, ident: str, column: str) -> str:
    """Refuse to emit a cell that would corrupt the table it is written into."""
    if "\n" in value:
        raise GeneratorBug(f"{ident}: {column} contains a newline; it cannot go in a table cell")
    if CELL_SPLIT_RE.search(value):
        raise GeneratorBug(
            f"{ident}: {column} contains an unescaped '|'; it would split the row. "
            f"Escape it as '\\|' at the source. Value: {value[:80]!r}"
        )
    return value


# --------------------------------------------------------------------------------------
# Source records
# --------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Criterion:
    id: str
    name: str
    round: int
    priority: str
    where: str


@dataclasses.dataclass(frozen=True)
class NotCoveredEntry:
    id: str
    name: str
    reason: str
    where: str


@dataclasses.dataclass(frozen=True)
class Verdict:
    id: str
    priority: str
    status: str
    evidence: str
    round: int
    where: str


@dataclasses.dataclass(frozen=True)
class TrackerRow:
    id: str
    name: str
    rnd: str        # "1".."N" or the literal "not_covered"
    priority: str
    status: str     # canonical, decoration stripped
    evidence: str
    notes: str
    where: str
    raw: str        # the committed line, verbatim -- see check_whitespace_normalisation


@dataclasses.dataclass(frozen=True)
class RoundClaim:
    """What a round doc says about itself, in prose -- used only to cross-check.

    XDR's docs carry a `| Status | All (134) | core (27) |` block; XSIAM's carry a
    `**Result:** 55 pass . 0 fail . 0 blocked . 0 not run` line. Neither is a data
    source (neither names a single ID), but both are a claim that can be held against
    the rows, and Round 2 of XDR is exactly why that matters: it claims 49 pass and
    57 blocked for criteria the tracker still lists as not_run.
    """
    round: int
    counts: dict
    where: str


# --------------------------------------------------------------------------------------
# TEST_PLAN.md -- the inventory
# --------------------------------------------------------------------------------------

def read_plan(path: Path) -> tuple[dict, dict]:
    """Parse TEST_PLAN.md into (criteria by id, not_covered by id)."""
    if not path.exists():
        raise ParseError(path, 0, "TEST_PLAN.md is missing; there is no inventory to generate from")

    lines = path.read_text(encoding="utf-8").splitlines()
    criteria: dict[str, Criterion] = {}
    not_covered: dict[str, NotCoveredEntry] = {}

    current_round: int | None = None
    in_not_covered = False
    awaiting_priority: tuple[str, int] | None = None   # (id, heading lineno)

    for idx, line in enumerate(lines):
        lineno = idx + 1

        if line.startswith("# "):
            match = PLAN_H1_ROUND_RE.match(line)
            current_round = int(match.group(1)) if match else None
            in_not_covered = bool(PLAN_H1_NOTCOVERED_RE.match(line))
            if awaiting_priority:
                cid, hline = awaiting_priority
                raise ParseError(path, hline, f"{cid}: criterion heading has no priority line under it")
            awaiting_priority = None
            continue

        # The not-covered table ends at the next heading of ANY level. XSIAM keeps a
        # second, 2-column `## Reachability probes (3)` table under the same H1; reading
        # on would misfile RULE-011/038/039 as not_covered when all three are live
        # round-3 criteria with passing verdicts.
        if in_not_covered and line.startswith("#"):
            in_not_covered = False

        if line.startswith("### "):
            match = PLAN_CRITERION_RE.match(line)
            if match:
                if current_round is None:
                    raise ParseError(
                        path, lineno,
                        f"criterion {match.group(1)} sits outside any '# Round N' section; "
                        "its round cannot be determined",
                    )
                cid, name = match.group(1), match.group(2)
                if cid in criteria:
                    raise ParseError(path, lineno, f"{cid} is defined twice ({criteria[cid].where} and here)")
                criteria[cid] = Criterion(cid, name, current_round, "", f"{path.name}:{lineno}")
                awaiting_priority = (cid, lineno)
            elif current_round is not None:
                # Inside a round section every `###` is a criterion. A stray one means the
                # heading form changed, which would silently shrink the inventory.
                raise ParseError(
                    path, lineno,
                    f"level-3 heading inside Round {current_round} is not a criterion "
                    f"heading (expected '### `ID` Name'): {line.strip()!r}",
                )
            continue

        if awaiting_priority and line.strip():
            cid, hline = awaiting_priority
            match = PLAN_PRIORITY_RE.match(line.strip())
            if not match:
                raise ParseError(
                    path, lineno,
                    f"{cid}: expected the priority line (*core* / *supporting* / *low*) "
                    f"under the heading at line {hline}, found {line.strip()[:60]!r}",
                )
            criteria[cid] = dataclasses.replace(criteria[cid], priority=match.group(1))
            awaiting_priority = None
            continue

        if in_not_covered and line.startswith("|"):
            if is_table_furniture(line):
                continue
            match = ID_ROW_RE.match(line)
            if not match:
                raise ParseError(
                    path, lineno,
                    f"row in the '# Not covered' table does not start with a `ID` cell: {line[:80]!r}",
                )
            cells = split_cells(line)
            if len(cells) < 3:
                raise ParseError(
                    path, lineno,
                    f"not-covered row for {match.group(1)} has {len(cells)} cells, expected at least 3 "
                    "(ID, Capability, Reason)",
                )
            cid = match.group(1)
            if cid in criteria:
                raise ParseError(
                    path, lineno,
                    f"{cid} is listed as not_covered but also has a criterion at {criteria[cid].where}",
                )
            if cid in not_covered:
                raise ParseError(path, lineno, f"{cid} appears twice in the not-covered table")
            not_covered[cid] = NotCoveredEntry(cid, cells[1], cells[2], f"{path.name}:{lineno}")

    if awaiting_priority:
        cid, hline = awaiting_priority
        raise ParseError(path, hline, f"{cid}: criterion heading has no priority line under it")

    if not criteria:
        raise ParseError(path, 0, "no criteria found; the plan's heading format must have changed")

    return criteria, not_covered


# --------------------------------------------------------------------------------------
# docs/rounds/ROUND<N>_RESULTS.md -- the verdicts
# --------------------------------------------------------------------------------------

def parse_status(cell: str, edition: Edition, path: Path, lineno: int) -> str:
    """Canonicalise a rendered status cell ('✅ pass', '— not_covered', 'pass') -> 'pass'."""
    text = cell.strip()
    for status, rendered in edition.status_render.items():
        if text == rendered:
            return status
    if text in STATUSES:
        return text
    raise ParseError(
        path, lineno,
        f"unknown status {cell!r}; expected one of {', '.join(STATUSES)} "
        "(optionally with this edition's decoration)",
    )


def read_round_docs(rounds_dir: Path, edition: Edition, plan_rounds: set) -> tuple[dict, list, list]:
    """Parse every ROUND<N>_RESULTS.md. Returns (verdicts by id, claims, findings)."""
    verdicts: dict[str, Verdict] = {}
    claims: list[RoundClaim] = []
    findings: list[Finding] = []

    if not rounds_dir.is_dir():
        findings.append(Finding("NOTE", "rounds", f"{rounds_dir} does not exist; no verdict tables to read"))
        return verdicts, claims, findings

    for path in sorted(rounds_dir.iterdir()):
        match = ROUND_DOC_RE.match(path.name)
        if not match:
            continue
        round_no = int(match.group(1))
        lines = path.read_text(encoding="utf-8").splitlines()

        claim = read_round_claim(round_no, lines, path)
        if claim:
            claims.append(claim)

        # Anchor on the section, not on the file. Both editions' round docs open with a
        # `## Runs` table whose rows also lead with a backticked token
        # (`| \`r1a-baseline\` | \`/usr,/var\` | ... |`); a whole-file scan for
        # backtick-led rows pulls those in and inflates 55/107/114 to 69/112/120.
        section = next((i for i, l in enumerate(lines) if l.strip() == VERDICT_SECTION), None)
        if section is None:
            if round_no not in plan_rounds:
                # XDR's ROUND4_RESULTS.md is a dataset-management round with its own D-numbered
                # criteria; the plan defines no round 4 and none of those IDs is a capability ID.
                # Absent verdicts there are expected, not a gap in this tracker.
                findings.append(Finding(
                    "NOTE", f"round {round_no}",
                    f"{path.name} documents a round TEST_PLAN.md does not define; no capability-ID "
                    "verdicts are expected from it and none were read",
                ))
            else:
                findings.append(Finding(
                    "GAP", f"round {round_no}",
                    f"{path.name} has no '{VERDICT_SECTION}' table -- this round records no per-ID "
                    "verdict anywhere, so its rows can only be carried forward from the committed tracker",
                ))
            continue

        count_here = 0
        for idx in range(section + 1, len(lines)):
            line = lines[idx]
            lineno = idx + 1
            if not line.strip().startswith("|"):
                # The verdict table is the last thing in every round doc that has one.
                # Anything non-pipe after it that is not blank means the layout moved.
                if line.strip() and count_here:
                    raise ParseError(
                        path, lineno,
                        f"content after the '{VERDICT_SECTION}' table: {line.strip()[:60]!r}. "
                        "The verdict table must be the last section of the file.",
                    )
                continue
            if is_table_furniture(line):
                continue
            match_row = ID_ROW_RE.match(line)
            if not match_row:
                raise ParseError(
                    path, lineno,
                    f"row under '{VERDICT_SECTION}' does not start with a `ID` cell: {line[:80]!r}",
                )
            cells = split_cells(line)
            if len(cells) != 5:
                raise ParseError(
                    path, lineno,
                    f"verdict row for {match_row.group(1)} has {len(cells)} cells, expected 5 "
                    "(ID, Capability, Pri, Status, Evidence). If the evidence contains a literal "
                    "pipe it must be written '\\|'.",
                )
            cid = cells[0].strip("`")
            if cid in verdicts:
                raise ParseError(
                    path, lineno,
                    f"{cid} already has a verdict at {verdicts[cid].where}; "
                    "one criterion cannot be decided twice",
                )
            verdicts[cid] = Verdict(
                id=cid,
                priority=cells[2],
                status=parse_status(cells[3], edition, path, lineno),
                evidence=cells[4],
                round=round_no,
                where=f"{path.name}:{lineno}",
            )
            count_here += 1

        if count_here == 0:
            raise ParseError(path, section + 1, f"'{VERDICT_SECTION}' section is present but empty")

    return verdicts, claims, findings


_CLAIM_RESULT_RE = re.compile(
    r"^\*\*Result:\*\*\s*(\d+)\s*pass\D+(\d+)\s*fail\D+(\d+)\s*blocked\D+(\d+)\s*not run", re.I
)
_CLAIM_TABLE_HEAD_RE = re.compile(r"^\|\s*Status\s*\|")
_CLAIM_TABLE_ROW_RE = re.compile(r"^\|\s*(pass|fail|blocked|not[_ ]run)\s*\|\s*(\d+)\s*\|")


def read_round_claim(round_no: int, lines: list[str], path: Path) -> RoundClaim | None:
    """Read a round doc's own prose summary of its outcome, if it has one.

    Advisory only: this never feeds a row. It exists so the generator can say
    "your Round 2 doc claims 49 pass, your tracker says 0" instead of leaving the two
    to disagree in silence for another six months.
    """
    counts: dict[str, int] = {}
    for line in lines:
        match = _CLAIM_RESULT_RE.match(line.strip())
        if match:
            counts = {
                "pass": int(match.group(1)),
                "fail": int(match.group(2)),
                "blocked": int(match.group(3)),
                "not_run": int(match.group(4)),
            }
            break
    if not counts:
        in_table = False
        for line in lines:
            if _CLAIM_TABLE_HEAD_RE.match(line.strip()):
                in_table = True
                continue
            if in_table:
                row = _CLAIM_TABLE_ROW_RE.match(line.strip())
                if row:
                    counts[row.group(1).replace(" ", "_")] = int(row.group(2))
                elif line.strip().startswith("|---"):
                    continue
                else:
                    break
    if not counts:
        return None
    return RoundClaim(round=round_no, counts=counts, where=path.name)


# --------------------------------------------------------------------------------------
# TEST_TRACKING.md -- the carry-forward store
# --------------------------------------------------------------------------------------

def read_tracker(path: Path, edition: Edition) -> tuple[dict, list, dict | None]:
    """Parse the committed tracker. Returns (rows by id, id order, committed header)."""
    if not path.exists():
        return {}, [], None

    lines = path.read_text(encoding="utf-8").splitlines()
    rows: dict[str, TrackerRow] = {}
    order: list[str] = []

    body = next((i for i, l in enumerate(lines) if l.strip() == "## All capabilities"), None)
    if body is None:
        raise ParseError(path, 1, "no '## All capabilities' section; this is not a tracker file")

    for idx in range(body + 1, len(lines)):
        line = lines[idx]
        lineno = idx + 1
        if not line.strip().startswith("|"):
            continue
        if is_table_furniture(line):
            continue
        match = ID_ROW_RE.match(line)
        if not match:
            raise ParseError(
                path, lineno,
                f"row in '## All capabilities' does not start with a `ID` cell: {line[:80]!r}",
            )
        cells = split_cells(line)
        if len(cells) != 7:
            raise ParseError(
                path, lineno,
                f"tracker row for {match.group(1)} has {len(cells)} cells, expected 7 "
                "(ID, Capability, Rnd, Pri, Status, Evidence, Notes). A literal pipe inside a "
                "cell must be written '\\|'.",
            )
        cid = cells[0].strip("`")
        if cid in rows:
            raise ParseError(path, lineno, f"{cid} appears twice; the tracker has one row per capability")
        rows[cid] = TrackerRow(
            id=cid,
            name=cells[1],
            rnd=cells[2],
            priority=cells[3],
            status=parse_status(cells[4], edition, path, lineno),
            evidence=cells[5],
            notes=cells[6],
            where=f"{path.name}:{lineno}",
            raw=line.rstrip("\n"),
        )
        order.append(cid)

    # CENSUS. Everything above only validates lines that reached the parser; a line the
    # loop never considered is, by construction, invisible to it. That is not hypothetical:
    # deleting the single leading '|' from a row makes `line.strip().startswith("|")` false,
    # the `continue` fires, and the row is dropped with no error and exit 0. Measured on a
    # real file -- 467 rows became 466, taking RULE-053's `blocked` verdict and its evidence
    # string with it.
    #
    # That is the worst possible place for a silent skip. XDR's 134 Round-1 verdicts exist
    # ONLY in this file: no round doc carries them, so a dropped row is not recoverable by
    # regenerating, and the next write makes the loss permanent and internally consistent.
    #
    # So rather than patch the one mangling we happened to find, count what the file CLAIMS
    # to contain and compare it against what we parsed. Any capability ID that appears in
    # the body but did not become a row is a parse failure, whatever shape the damage took.
    # Scoped to PREFIX_ORDER and to backticked tokens on purpose. A bare `[A-Z]+-\d{3}`
    # also matches prose like "SHA-256" sitting in an evidence cell, which would make the
    # census cry wolf on a perfectly good file -- and a check that fires on healthy input is
    # one that gets disabled.
    seen_in_text: dict[str, int] = {}
    for idx in range(body + 1, len(lines)):
        for cid in CENSUS_ID_RE.findall(lines[idx]):
            seen_in_text.setdefault(cid, idx + 1)
    missed = sorted(set(seen_in_text) - set(rows))
    if missed:
        first = missed[0]
        raise ParseError(
            path, seen_in_text[first],
            f"{len(missed)} capability id(s) appear in the table body but were not parsed as "
            f"rows: {', '.join(missed[:5])}{' ...' if len(missed) > 5 else ''}. A row whose "
            f"leading '|' is missing or damaged is skipped rather than read, and for Round-1 "
            f"rows this file is the only record of the verdict -- so this is refused rather "
            f"than written through.",
        )

    return rows, order, read_committed_header(lines)


_EXECUTED_RE = re.compile(r"\*\*(\d+) of (\d+) executed")


def read_committed_header(lines: list[str]) -> dict | None:
    """Read the committed Progress block so its numbers can be quoted back at it.

    Tolerant on purpose: this is the block being replaced, and it may be in any historic
    shape. Failing to read it must not stop the regeneration -- it only costs the run one
    finding, and the whole-file diff still shows the change.
    """
    start = next((i for i, l in enumerate(lines) if l.strip() == "## Progress"), None)
    if start is None:
        return None
    header: dict = {"rows": {}, "executed": None}
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        match = _EXECUTED_RE.search(line)
        if match:
            header["executed"] = (int(match.group(1)), int(match.group(2)))
            continue
        if line.strip().startswith("|") and not is_table_furniture(line):
            cells = split_cells(line)
            label = cells[0].strip("* ")
            numbers = []
            for cell in cells[1:]:
                digits = cell.strip("* ")
                numbers.append(int(digits) if digits.isdigit() else None)
            header["rows"][label] = numbers
    return header


# --------------------------------------------------------------------------------------
# Row assembly
# --------------------------------------------------------------------------------------

@dataclasses.dataclass
class Row:
    id: str
    name: str
    rnd: str
    priority: str
    status: str
    evidence: str
    notes: str


def sort_key(cid: str) -> tuple[int, int]:
    prefix, number = cid.split("-")
    if prefix not in PREFIX_ORDER:
        raise GeneratorBug(
            f"{cid}: prefix {prefix!r} is not in PREFIX_ORDER {PREFIX_ORDER}. "
            "A new capability family needs a deliberate position in the table, "
            "not whatever the sort happens to do."
        )
    return PREFIX_ORDER.index(prefix), int(number)


def build_rows(edition, criteria, not_covered, verdicts, tracker_rows, claims):
    """Merge every source into the final row list, reporting each disagreement."""
    findings: list[Finding] = []

    inventory = set(criteria) | set(not_covered)

    # A verdict for an ID the inventory has never heard of is the one thing we refuse to
    # act on: "never invent a capability ID" cuts both ways, and a typo'd ID in a round
    # doc would otherwise materialise as a brand-new capability.
    for cid, verdict in sorted(verdicts.items()):
        if cid not in inventory:
            raise ParseError(
                Path(verdict.where.split(":")[0]), int(verdict.where.split(":")[1]),
                f"verdict for {cid}, which is not in TEST_PLAN.md -- neither as a criterion "
                "nor in the not-covered table",
            )

    for cid in sorted(set(tracker_rows) - inventory):
        findings.append(Finding(
            "DRIFT", cid,
            f"row exists in the committed tracker ({tracker_rows[cid].where}) but the ID is not in "
            "TEST_PLAN.md; the generated tracker drops it",
        ))

    rows: list[Row] = []
    for cid in sorted(inventory, key=sort_key):
        committed = tracker_rows.get(cid)
        verdict = verdicts.get(cid)
        criterion = criteria.get(cid)
        nc = not_covered.get(cid)

        # ---- capability name: the plan, always -------------------------------------
        name = criterion.name if criterion else nc.name
        if committed and committed.name != name:
            findings.append(Finding(
                "DRIFT", cid,
                f"capability text differs: plan has {name!r}, tracker has {committed.name!r} "
                "-- taking the plan",
            ))

        # ---- round -----------------------------------------------------------------
        rnd = str(criterion.round) if criterion else "not_covered"
        if committed and committed.rnd != rnd:
            findings.append(Finding(
                "DRIFT", cid,
                f"round differs: plan says {rnd}, tracker says {committed.rnd} -- taking the plan",
            ))

        # ---- priority ---------------------------------------------------------------
        if criterion:
            priority = criterion.priority
            if committed and committed.priority != priority:
                findings.append(Finding(
                    "DRIFT", cid,
                    f"priority differs: plan says {priority}, tracker says {committed.priority} "
                    "-- taking the plan",
                ))
            if verdict and verdict.priority and verdict.priority != priority:
                findings.append(Finding(
                    "DRIFT", cid,
                    f"priority differs: plan says {priority}, {verdict.where} says {verdict.priority} "
                    "-- taking the plan",
                ))
        else:
            # The plan's not-covered table has no priority column, in either edition.
            # The committed tracker is the only place these values have ever existed.
            if committed and committed.priority:
                priority = committed.priority
            else:
                priority = EM_DASH
                findings.append(Finding(
                    "GAP", cid,
                    "not_covered row has no priority anywhere (the plan's not-covered table has no "
                    "priority column and the tracker has no row to carry forward)",
                ))

        # ---- status and evidence ----------------------------------------------------
        if verdict:
            status = verdict.status
            evidence = clamp_cell(verdict.evidence) or EM_DASH
            if criterion and verdict.round != criterion.round:
                findings.append(Finding(
                    "DRIFT", cid,
                    f"verdict is filed in round {verdict.round} ({verdict.where}) but the plan puts "
                    f"the criterion in round {criterion.round}",
                ))
            if nc:
                findings.append(Finding(
                    "DRIFT", cid,
                    f"listed as not_covered in the plan but {verdict.where} records a verdict of "
                    f"{verdict.status} -- taking the verdict",
                ))
            if committed:
                if committed.status != status:
                    findings.append(Finding(
                        "DRIFT", cid,
                        f"status differs: {verdict.where} says {status}, tracker says "
                        f"{committed.status} -- taking the round doc",
                    ))
                if committed.evidence != evidence:
                    if verdict.evidence.startswith(evidence.rstrip(ELLIPSIS)) and \
                       committed.evidence != verdict.evidence:
                        findings.append(Finding(
                            "NOTE", cid,
                            f"evidence in {verdict.where} is {len(verdict.evidence)} chars; the "
                            f"tracker's {CELL_LIMIT}-char cell cap trims it to {len(evidence)}",
                        ))
                    else:
                        findings.append(Finding(
                            "DRIFT", cid,
                            f"evidence differs: {verdict.where} has {verdict.evidence[:60]!r}..., "
                            f"tracker has {committed.evidence[:60]!r}... -- taking the round doc",
                        ))
        elif committed and committed.status != "not_run":
            # No verdict table covers this row, but the committed tracker records a real
            # outcome. That is XDR Round 1's 134 rows: the tracker is their only record.
            status = committed.status
            evidence = clamp_cell(committed.evidence) if committed.evidence else EM_DASH
        elif nc:
            status = "not_covered"
            evidence = clamp_cell(committed.evidence) if committed and committed.evidence else EM_DASH
        else:
            status = "not_run"
            evidence = EM_DASH

        # An ID whose only disposition is not_covered keeps not_covered -- including when
        # a stale tracker row says otherwise.
        if nc and not verdict and status != "not_covered":
            findings.append(Finding(
                "DRIFT", cid,
                f"the plan lists this as not_covered but the tracker says {status} "
                "-- taking not_covered",
            ))
            status = "not_covered"

        # ---- notes: carry-forward only ----------------------------------------------
        notes = committed.notes if committed and committed.notes else EM_DASH
        # Notes are carry-forward only: this file is their sole home, so a clamp here is a
        # one-way trim of the only copy. Evidence gets a cap NOTE and notes did not, which
        # is backwards -- evidence can be rebuilt from a round doc, notes cannot. Headroom
        # is already nil (XSIAM's longest note is 198 against a 200 cap), so this fires the
        # first time anyone writes a slightly longer justification.
        clamped_notes = clamp_cell(notes)
        if clamped_notes != notes:
            findings.append(Finding(
                "DRIFT", cid,
                f"Notes is {len(notes)} chars and the {CELL_LIMIT}-char cap trims it to "
                f"{len(clamped_notes)}. No other file carries a Notes column, so the trimmed "
                f"text is lost on write -- shorten it in the tracker deliberately, or raise "
                f"CELL_LIMIT.",
            ))
        notes = clamped_notes

        rows.append(Row(
            id=cid, name=name, rnd=rnd, priority=priority,
            status=status, evidence=evidence or EM_DASH, notes=notes or EM_DASH,
        ))

    findings.extend(check_round_coverage(criteria, verdicts, rows, claims))
    return rows, findings


def check_round_coverage(criteria, verdicts, rows, claims):
    """Report rounds with no verdict table, and round docs whose own totals disagree."""
    findings: list[Finding] = []
    by_round: dict[int, list[Row]] = {}
    for row in rows:
        if row.rnd.isdigit():
            by_round.setdefault(int(row.rnd), []).append(row)

    verdict_rounds = {v.round for v in verdicts.values()}
    for round_no in sorted(by_round):
        members = by_round[round_no]
        if round_no not in verdict_rounds:
            executed = sum(1 for r in members if r.status not in ("not_run",))
            findings.append(Finding(
                "GAP", f"round {round_no}",
                f"{len(members)} criteria, no per-ID verdict table in docs/rounds/ -- "
                f"{executed} carry a status only because the committed tracker says so, and "
                f"{len(members) - executed} are still not_run. --check cannot validate either group.",
            ))

    derived = {}
    for round_no, members in by_round.items():
        counts = {s: 0 for s in STATUSES}
        for row in members:
            counts[row.status] += 1
        derived[round_no] = counts

    for claim in claims:
        counts = derived.get(claim.round)
        if not counts:
            continue
        for status, claimed in claim.counts.items():
            actual = counts.get(status, 0)
            if claimed != actual:
                findings.append(Finding(
                    "DRIFT", f"round {claim.round}",
                    f"{claim.where} claims {claimed} {status}; the generated rows have {actual}"
                    + (" -- the round ran but was never written back"
                       if actual == 0 and claimed else ""),
                ))
    return findings


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------

def render(edition: Edition, rows: list[Row]) -> str:
    """Render the whole file. EVERY number below is counted from `rows`."""
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        counts.setdefault(row.rnd, {s: 0 for s in STATUSES})[row.status] += 1

    round_labels = sorted((k for k in counts if k.isdigit()), key=int)
    labels = round_labels + [k for k in counts if not k.isdigit()]

    # Invariant 1: every row lands in exactly one label bucket.
    if sum(sum(c.values()) for c in counts.values()) != len(rows):
        raise GeneratorBug("progress buckets do not sum to the number of rows")

    columns = ["pass", "fail", "blocked", "not_run", "not_covered"]
    body_lines = []
    totals = {s: 0 for s in STATUSES}
    for label in labels:
        bucket = counts[label]
        total = sum(bucket.values())
        # Invariant 2: a row's Total is the sum of the status cells beside it. This is the
        # property the old hand-written header lacked -- "1 | 134 | 0 | 0 | 0 | 134" added
        # up perfectly and was still false, because nothing tied it to the rows.
        if total != sum(bucket[c] for c in columns):
            raise GeneratorBug(f"round {label}: status columns do not sum to its total")
        for status in STATUSES:
            totals[status] += bucket[status]
        body_lines.append("| " + " | ".join([label, str(total)] + [str(bucket[c]) for c in columns]) + " |")

    grand = sum(totals.values())
    # Invariant 3: the All-rows line equals the number of rows actually written below.
    if grand != len(rows):
        raise GeneratorBug("the All-rows total does not equal the number of generated rows")

    body_lines.append(
        "| " + " | ".join(
            ["**All rows**", f"**{grand}**"] + [f"**{totals[c]}**" for c in columns]
        ) + " |"
    )

    testable = grand - totals["not_covered"]
    executed = totals["pass"] + totals["fail"] + totals["blocked"]

    out = [edition.preamble.rstrip("\n"), "", "## Progress", ""]
    out.append("| Round | Total | " + " | ".join(columns) + " |")
    out.append("|" + "---|" * (len(columns) + 2))
    out.extend(body_lines)
    out.append("")
    out.append(
        f"**{executed} of {testable} testable criteria executed.** "
        f"{totals['not_covered']} further capabilities are `not_covered` and are counted in the "
        f"table above; {grand} rows in total."
    )
    out.append("")
    # Spell the invariant out in the file itself. A reader who cannot run the tool should
    # still be able to check the arithmetic by eye -- which is exactly what nobody could do
    # with the old block, because it stated totals with no stated relationship to anything.
    out.append("Every number above is counted from the rows below by `tools/gen_tracking.py`:")
    out.append("each row's Total is the sum of the status cells beside it, and **All rows** is")
    out.append("the number of rows in the table. Do not edit this block by hand; run the generator.")
    out.append("")
    out.append("## All capabilities")
    out.append("")
    out.append(TRACKER_TABLE_HEADER)
    out.append(TRACKER_TABLE_RULE)

    out.extend(render_row(edition, row) for row in rows)

    return "\n".join(out) + "\n"


def render_row(edition: Edition, row: Row) -> str:
    cells = [
        f"`{row.id}`",
        check_writable_cell(row.name, row.id, "capability"),
        row.rnd,
        row.priority,
        edition.render_status(row.status),
        check_writable_cell(row.evidence, row.id, "evidence"),
        check_writable_cell(row.notes, row.id, "notes"),
    ]
    return "| " + " | ".join(cells) + " |"


def check_committed_header(committed: dict | None, rows: list[Row]) -> list[Finding]:
    """Quote the committed Progress block's numbers back at the rows it sits above."""
    if committed is None:
        return []
    findings: list[Finding] = []
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        counts.setdefault(row.rnd, {s: 0 for s in STATUSES})[row.status] += 1

    # The old header's columns were Total | pass | fail | blocked | not_run.
    old_columns = ["pass", "fail", "blocked", "not_run"]
    for label, numbers in committed["rows"].items():
        bucket = counts.get(label)
        if bucket is None or not numbers or numbers[0] is None:
            continue
        derived_total = sum(bucket.values())
        if numbers[0] != derived_total:
            findings.append(Finding(
                "DRIFT", "header",
                f"committed Progress row {label!r} says Total={numbers[0]}; the rows give {derived_total}",
            ))
        for i, column in enumerate(old_columns, start=1):
            if i < len(numbers) and numbers[i] is not None and numbers[i] != bucket[column]:
                findings.append(Finding(
                    "DRIFT", "header",
                    f"committed Progress row {label!r} says {column}={numbers[i]}; "
                    f"the rows give {bucket[column]}",
                ))

    covered = sum(1 for r in rows if r.status == "not_covered")
    testable = len(rows) - covered
    executed = sum(1 for r in rows if r.status in ("pass", "fail", "blocked"))
    if committed["executed"]:
        claimed_exec, claimed_total = committed["executed"]
        if (claimed_exec, claimed_total) != (executed, testable):
            findings.append(Finding(
                "DRIFT", "header",
                f"committed header says '{claimed_exec} of {claimed_total} executed'; "
                f"the rows give {executed} of {testable}",
            ))
    if covered and committed["executed"] and committed["executed"][1] == len(rows) - covered \
            and not any(label == "not_covered" for label in committed["rows"]):
        findings.append(Finding(
            "DRIFT", "header",
            f"committed Progress table omits the {covered} not_covered rows entirely, so it "
            f"accounts for {sum(1 for r in rows if r.rnd.isdigit())} of {len(rows)} rows",
        ))
    return findings


def check_whitespace_normalisation(edition, tracker_rows, rows) -> list[Finding]:
    """Report cells whose committed text carries stray padding the generator trims.

    Both trackers were truncated by hand, and some cuts landed on a space, leaving cells
    that end in whitespace: `... consistent with the cap but not  |`. Reading strips it and
    writing does not put it back, so the row changes without any fact changing. That is
    still a change to a committed file, so it is named rather than slipped through -- but
    it is one aggregated NOTE, not fifteen, because the content is identical by definition.
    """
    squash = lambda text: re.sub(r"\s+", "", text)
    affected = []
    for row in rows:
        committed = tracker_rows.get(row.id)
        if not committed:
            continue
        generated = render_row(edition, row)
        if committed.raw != generated and squash(committed.raw) == squash(generated):
            affected.append(row.id)
    if not affected:
        return []
    return [Finding(
        "NOTE", "whitespace",
        f"{len(affected)} committed rows differ from the generated ones only in cell padding "
        f"(hand truncation left a trailing space inside the cell): "
        f"{', '.join(affected[:6])}{' ...' if len(affected) > 6 else ''}",
    )]


def check_row_order(committed_order: list[str], rows: list[Row]) -> list[Finding]:
    generated = [r.id for r in rows]
    if not committed_order or committed_order == generated:
        return []
    for position, (was, now) in enumerate(zip(committed_order, generated), start=1):
        if was != now:
            return [Finding(
                "DRIFT", "order",
                f"row order diverges at position {position}: committed has {was}, generated has {now}",
            )]
    return [Finding(
        "DRIFT", "order",
        f"committed tracker has {len(committed_order)} rows, generated has {len(generated)}",
    )]


# --------------------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------------------

def generate(root: Path, edition: Edition) -> tuple[str, list[Finding], Path]:
    docs = root / edition.key / "docs"
    plan_path = docs / "TEST_PLAN.md"
    tracker_path = docs / "TEST_TRACKING.md"

    criteria, not_covered = read_plan(plan_path)
    plan_rounds = {c.round for c in criteria.values()}
    verdicts, claims, findings = read_round_docs(docs / "rounds", edition, plan_rounds)
    tracker_rows, committed_order, committed_header = read_tracker(tracker_path, edition)

    rows, merge_findings = build_rows(edition, criteria, not_covered, verdicts, tracker_rows, claims)
    findings += merge_findings
    findings += check_committed_header(committed_header, rows)
    findings += check_row_order(committed_order, rows)
    findings += check_whitespace_normalisation(edition, tracker_rows, rows)

    if tracker_rows:
        carried = sum(
            1 for r in rows
            if r.id not in verdicts and r.id in tracker_rows and r.status not in ("not_run", "not_covered")
        )
        if carried:
            findings.append(Finding(
                "NOTE", "carry-forward",
                f"{carried} rows take their status/evidence from the committed tracker because no "
                "round doc records them; --check compares those cells against themselves and can "
                "never fail on them",
            ))
        notes_carried = sum(1 for r in rows if r.notes != EM_DASH)
        if notes_carried:
            findings.append(Finding(
                "NOTE", "carry-forward",
                f"{notes_carried} Notes cells are carried forward; no other file has a Notes column",
            ))

    text = render(edition, rows)
    return text, findings, tracker_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate TEST_TRACKING.md from TEST_PLAN.md and the round result docs.",
    )
    parser.add_argument("--edition", required=True, choices=sorted(EDITIONS))
    parser.add_argument("--check", action="store_true",
                        help="regenerate in memory and diff against the committed file; "
                             "exit non-zero if they differ")
    parser.add_argument("--stdout", action="store_true", help="print the result instead of writing it")
    parser.add_argument("--force", action="store_true",
                        help="write even when regenerating would REMOVE committed rows. Their "
                             "Notes cells exist in no other file; there is no undo.")
    parser.add_argument("--out", type=Path, default=None,
                        help="write somewhere other than <edition>/docs/TEST_TRACKING.md")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="repository root (default: the parent of tools/)")
    args = parser.parse_args(argv)

    edition = EDITIONS[args.edition]

    try:
        text, findings, tracker_path = generate(args.root.resolve(), edition)
    except ParseError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        print("Refusing to generate a tracker from a source I cannot read in full: a short "
              "table looks exactly like a deliberately retired capability.", file=sys.stderr)
        return 2
    except GeneratorBug:
        # Keep the traceback -- this is a defect in this file, not in the data, and the
        # stack is the useful part. But exit 2, not 1: 1 is reserved for "--check found a
        # difference", and CI must be able to tell a stale tracker from a broken tool.
        import traceback
        traceback.print_exc()
        print("FATAL: internal invariant failed; nothing was written.", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: (KIND_ORDER.get(f.kind, 9), f.subject, f.message))
    drift = [f for f in findings if f.kind == "DRIFT"]

    # Findings go to stderr, not stdout. `--stdout` has to be able to write the file itself
    # into a pipe (`... --stdout > TEST_TRACKING.md`) and `--check` has to be able to write
    # a clean patch; mixing the diagnostics into either stream would corrupt both.
    print(f"== {edition.key}: {len(text.splitlines())} lines generated, "
          f"{len(findings)} findings ({len(drift)} DRIFT)", file=sys.stderr)
    for finding in findings:
        print(finding.line(), file=sys.stderr)

    if args.check:
        if not tracker_path.exists():
            print(f"FATAL: --check needs {tracker_path}, which does not exist", file=sys.stderr)
            return 2
        committed = tracker_path.read_text(encoding="utf-8")
        diff = list(difflib.unified_diff(
            committed.splitlines(keepends=True),
            text.splitlines(keepends=True),
            fromfile=f"{tracker_path} (committed)",
            tofile=f"{tracker_path} (generated)",
        ))
        if diff:
            sys.stdout.writelines(diff)
            print(f"\n{edition.key}: committed tracker differs from the generated one "
                  f"({sum(1 for l in diff if l.startswith('+') and not l.startswith('+++'))} added, "
                  f"{sum(1 for l in diff if l.startswith('-') and not l.startswith('---'))} removed). "
                  "Run without --check to update it.", file=sys.stderr)
            return 1
        if drift:
            print(f"{edition.key}: file matches, but {len(drift)} DRIFT findings remain.",
                  file=sys.stderr)
            return 1
        print(f"{edition.key}: committed tracker is byte-identical to the generated one.",
              file=sys.stderr)
        return 0

    if args.stdout:
        sys.stdout.write(text)
        return 0

    # Writing is the irreversible half of this tool, and row removal is the only finding
    # that destroys information rather than correcting it. --check would have caught it, but
    # a generator that only fails under a flag you have to remember is not a safety net.
    removals = [f for f in drift if "the generated tracker drops it" in f.message]
    if removals and not args.force:
        print(f"REFUSING TO WRITE: {len(removals)} row(s) would be removed:", file=sys.stderr)
        for f in removals[:10]:
            print(f"  - {f.subject}", file=sys.stderr)
        print("Re-run with --force if the capabilities really were retired. Their Notes cells "
              "exist in no other file and will not come back.", file=sys.stderr)
        return 3

    destination = args.out or tracker_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    print(f"wrote {destination}", file=sys.stderr)
    if removals:
        print(f"WARNING: wrote with --force; {len(removals)} row(s) removed.", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
