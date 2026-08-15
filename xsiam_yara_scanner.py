"""
YARA Scanner (XSIAM Webhook Edition)
==================================
Enterprise-grade file scanner with real-time threat detection and Cortex XSIAM webhook reporting.

Features:
- Multi-threaded scanning with configurable workers
- Real-time XSIAM webhook reporting
- Scan caching for enhanced performance (Roadmap)
- Comprehensive logging and statistics
- Circuit breaker for upload resilience
- System resource monitoring

    VERSION : 4.3.0
    RELEASED: 2026-08-14
    SOURCE  : https://github.com/ayman-m/yarascanner
    NOTES   : https://github.com/ayman-m/yarascanner/blob/main/CHANGELOG.md

Report the version with any support request.
"""

__version__ = "4.3.0"
__release_date__ = "2026-08-14"

# Standard library imports
import base64
import ctypes
import datetime
import hashlib
import json
import logging
import os
import platform
import random
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback
import zipfile
import zlib
from collections import defaultdict, deque, OrderedDict
from enum import Enum
from queue import Queue, Empty, Full

# Platform-specific imports

# Third-party imports
import psutil
import requests
import yara

# ============================================================================
# CONSTANTS
# ============================================================================

def _env_number(name, default, cast=float, minimum=None):
    """Read a numeric tuning env var without letting a deployer typo (e.g. '60s',
    'unlimited') crash the whole scanner at import time - fall back to default and warn.

    `minimum` additionally rejects values that PARSE but are unusable. Parsing is not
    validation: YARA_MAX_MB=-1 is a perfectly good int that made max_file_bytes negative,
    so every file failed the size check and the scan reported "completed" having scanned
    nothing - a silent total loss of coverage whose only signal was a zero. Out-of-range
    falls back to the default for the same reason unparseable does: the deployer meant
    something, and the documented default is a safer guess than their broken value.
    """
    raw = os.environ.get(name, "")
    if not raw:
        return cast(default)
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        logging.warning(
            "Ignoring invalid %s=%r (expected a number) - using default %r",
            name, raw, default)
        return cast(default)
    if minimum is not None and value < minimum:
        logging.warning(
            "Ignoring out-of-range %s=%r (minimum %r) - using default %r",
            name, raw, minimum, default)
        return cast(default)
    return value


def _env_bool(name, default):
    """Read a boolean toggle constant below, honoring an env var override (for automation)
    without letting a malformed one crash the scanner at import time - same fail-safe
    pattern as _env_number. The literal True/False below is what a console deployer
    actually edits; the env var is an optional override on top of that."""
    raw = os.environ.get(name, "")
    if not raw:
        return bool(default)
    text = raw.strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    logging.warning(
        "Ignoring invalid %s=%r (expected true/false) - using default %r",
        name, raw, default)
    return bool(default)


UPLOAD_RESULTS = True  # Match and telemetry uploads to webhook
UPLOAD_NON_MATCH_DATA = True  # Keep telemetry uploads enabled in webhook mode
DEFAULT_TIMEOUT_SECS = 20            # increased request timeout everywhere
MAX_RETRIES_PER_ITEM = 2             # hard cap to avoid infinite loops
MAX_MATCH_SAMPLES_PER_FINDING = _env_number("YARA_MAX_MATCH_SAMPLES", 50, cast=int)
# ^ Ported from the XDR edition after it hit this live: one loosely-written rule matching one
# large file can produce tens of thousands of string-offset instances (measured there: 33,118
# rows from one rule against one .evtx log; measured here: 36,213 in one match-upload backlog),
# because the original design queued ONE upload item PER MATCHED STRING OFFSET. Fold all offsets
# for a given (rule, file) into ONE upload with a capped sample - full per-offset detail still
# is streamed to the local results file as it is produced; only the network representation
# is capped. Neither is buffered in memory.
BASE_BACKOFF_SECS = 1.0              # initial backoff
MAX_BACKOFF_SECS = 30.0              # backoff ceiling
CIRCUIT_FAILURE_THRESHOLD = 5        # open after N consecutive failures
CIRCUIT_RESET_TIMEOUT_SECS = 40      # stay open before probing again
WORKER_GET_TIMEOUT_SECS = 2.0        # queue.get timeout to allow graceful exit checks
THREAD_CLEANUP_TIMEOUT = 60          # Maximum time to wait for thread cleanup

# Backlog-proportional shutdown drain, ported from the XDR edition's lookup-uploader design:
# a flat drain window is either too short for a heavy scan's backlog (events get dropped, not
# delayed - confirmed live: a 12s scan's own "scan completed" event needed ~250s to actually
# reach the collector) or wastefully long for a light one. Scale the budget to queue size
# instead, same as XDR's LOOKUP_DRAIN_* constants.
#
# UNLIKE XDR - which drains one consolidated lookup-uploader queue - this edition has FOUR
# independent drain points (LogManager's webhook_queue plus three separate uploader classes'
# upload_queue). They drain sequentially at shutdown, so DRAIN_MAX_SECS is a per-site cap, not
# a total: confirmed live under concurrent fleet load that an earlier, more generous cap here
# (300s) let multiple sites each approach their max back-to-back, several times exceeding the
# snippet's own timeout and getting the whole process killed mid-drain by the agent - losing
# everything still queued, strictly worse than the flat-timeout bug this was meant to fix. Kept
# low enough that even all four sites maxing out at once (4 * 60s = 240s) stays well inside a
# normal script timeout.
# Cooperative cancellation. The console's own Cancel button hard-kills the payload process
# mid-scan (no flush, no summary, no terminal event), so an operator who wants a scan to stop
# WITHOUT losing what it already found needs this path instead: a flag file the running scan
# polls for. Ported from the XDR edition.
# Captured at MODULE IMPORT - as close to real process start as this file can observe, and
# critically BEFORE ScanConfig setup and rule compilation. The stale-flag check compares a
# cancel flag's mtime against this; anchoring it to YaraScanner.__init__ instead (which runs
# AFTER _compile_yara_rules) would judge any cancel delivered during a long compile as "stale
# from a previous run" and silently delete it - the exact failure the staleness logic exists
# to avoid.
_PROCESS_STARTED_AT = time.time()

# Floored: this is a poll interval, and _env_number only validates that the override parses
# as a number. A negative value would make time.sleep() raise (killing the watcher thread
# outright, leaving cancellation silently dead while running.json still advertises a live,
# cancellable scan); 0 would turn the watcher into a busy-spin on a scanner whose whole
# design goal is low host impact.
CANCEL_POLL_SECS = max(0.5, _env_number("YARA_CANCEL_POLL_SECS", 5))   # cancel-flag watcher cadence
CANCEL_STALE_TOLERANCE_SECS = 2.0  # mtime slack when judging a cancel flag stale (coarse-FS safety)
RUNNING_MARKER_REFRESH_SECS = 30.0  # how often a live scan refreshes running.json
RUNNING_MARKER_STALE_SECS = 180.0   # marker older than this => scan presumed dead

DRAIN_MIN_SECS = _env_number("YARA_DRAIN_MIN_SECS", 15)              # floor - matches prior fast-path behavior
DRAIN_PER_ITEM_SECS = _env_number("YARA_DRAIN_PER_ITEM_SECS", 0.3)   # rough per-POST budget incl. occasional retry
DRAIN_MAX_SECS = _env_number("YARA_DRAIN_MAX_SECS", 60)              # per-site ceiling (there are 4 sites - see above)


def _compute_drain_budget(pending_items):
    """Backlog-proportional shutdown drain budget - a storm scan's large backlog gets
    proportionally more time to flush; a normal scan's 1-2 pending items doesn't wait
    around at the floor for no reason. Capped so a dead collector can't hang shutdown."""
    return min(DRAIN_MAX_SECS, max(DRAIN_MIN_SECS, pending_items * DRAIN_PER_ITEM_SECS))


# Fixed sentinels for the shipped placeholder values, independent of DEFAULT_API_KEY/
# DEFAULT_API_ENDPOINT below - the deployment guide has editors overwrite THOSE constants
# directly, so comparing "still equals DEFAULT_API_KEY" can never detect a placeholder once
# the constant itself has been edited to a real value.
_PLACEHOLDER_API_KEY = "http_collector_key"
_PLACEHOLDER_API_ENDPOINT = "http_collector_api"

DEFAULT_API_KEY = "http_collector_key"
DEFAULT_API_ENDPOINT = "http_collector_api"

API_KEY = DEFAULT_API_KEY
API_ENDPOINT = DEFAULT_API_ENDPOINT

# Monitoring toggles - edit these directly (an env var of the same name still overrides,
# for automation/testing, but this literal is what a console deployer actually sees).
# Previously these were ONLY os.getenv() reads buried inside ScanConfig.__init__ with no
# constant here at all - unreachable in practice, since Action Center's "Run Script" has
# no way to set process environment variables; only editing the uploaded script works.
ENABLE_RESOURCE_MONITOR = _env_bool("YARA_ENABLE_RESOURCE_MONITOR", False)  # CPU/memory snapshots -> dashboard
ENABLE_PERF_MONITOR = _env_bool("YARA_ENABLE_PERF_MONITOR", False)
ENABLE_FD_MONITOR = _env_bool("YARA_ENABLE_FD_MONITOR", False)

# ---------------------------------------------------------------------------
# Upload batching (matches, telemetry, and logs all use these)
# ---------------------------------------------------------------------------
# The HTTP Collector accepts many events in ONE request as NDJSON - one JSON object
# per line, Content-Type: text/plain. Without batching each event cost its own POST,
# and a storm scan simply could not finish delivering: measured on a live endpoint,
# 23,223 findings at ~756 ms per POST would need ~4.9 HOURS, so the scan ended with
# 22,621 of them (97%) never sent. Batched at 500 the same run is ~47 requests, well
# inside the normal shutdown drain.
#
# Measured on the tenant, all delivered with zero loss:
#     10 events / 3.8 KB  -> 621 ms       1000 events / 391 KB -> 1075 ms
#    100 events /  38 KB  -> 685 ms       2000 events / 784 KB -> 1347 ms
#    500 events / 194 KB  -> 943 ms
# Latency is dominated by the round trip, not the payload, so larger batches are
# nearly free. 500 is the default rather than the 2000 ceiling that was probed:
# it keeps a request near 200 KB and leaves headroom for findings carrying unusually
# large matched strings.
#
# WARNING - do NOT switch this to a JSON array ([{...},{...}]). The collector answers
# HTTP 200 {"error":"false"} for an array and then silently discards every event in
# it (verified twice against the tenant). NDJSON is the only multi-event format that
# actually lands, and the failure mode for getting it wrong is invisible data loss.
# Batching is opportunistic, NOT timer-based: a worker blocks for the first event, then
# takes whatever is already queued behind it, up to these caps, and sends immediately. The
# batch size therefore self-adjusts to real load - a busy scan fills 500-event requests,
# and a scan with 3 matches sends a batch of 3 with no added latency. There is deliberately
# no "linger" timer: waiting to fill a batch would delay delivery on quiet scans to buy
# batching they do not need.
UPLOAD_BATCH_MAX_EVENTS = _env_number("YARA_UPLOAD_BATCH_MAX_EVENTS", 500, cast=int)
UPLOAD_BATCH_MAX_BYTES = _env_number("YARA_UPLOAD_BATCH_MAX_BYTES", 4 * 1024 * 1024, cast=int)

# Clamp: a batch of 0 would spin without ever sending.
UPLOAD_BATCH_MAX_EVENTS = max(1, UPLOAD_BATCH_MAX_EVENTS)
UPLOAD_BATCH_MAX_BYTES = max(64 * 1024, UPLOAD_BATCH_MAX_BYTES)

# --- Evidence packaging -----------------------------------------------------
# Whether the evidence ZIP carries copies of the matched files themselves.
#
# OFF by default, matching xdr_yara_scanner's collect_files, which was defaulted off at
# the customer's request. Copying is charged entirely to the SCANNED host's disk: every
# matched file is read and written into a local archive, so a scan that matches broadly
# writes gigabytes to the very machine the scan is meant not to disturb. A C:\Windows\System32
# scan on the lab host produced a 2.8 GB archive this way.
#
# Turning it off does NOT lose the ability to investigate: file_mapping.txt (every path
# plus its SHA256) and the per-rule alert texts are still packaged, so a responder can
# locate and pull any matched file by path or hash on demand. What is dropped is only the
# bulk pre-emptive copy of files that are, by definition, already on the host.
COLLECT_MATCHED_FILES = _env_bool("YARA_COLLECT_MATCHED_FILES", False)

# How many matched offsets alert/<rule>.txt renders per (rule, file) finding.
#
# The file used to render EVERY offset at ~95 bytes each. Measured on a live Windows
# endpoint, one rule against C:\Windows\System32 produced 2,433,386 offsets and a 220 MB
# file on the SCANNED HOST - 98.6% of it from four Windows event logs, where a rule hunting
# PowerShell strings legitimately matches thousands of times inside a PowerShell log.
#
# Individual offsets are not what an analyst works from: which host, which rule, which
# string IN that rule, and which file are. So the per-string-ID census is written in full
# and stays UNCAPPED - only the offsets themselves are sampled. That is the same deal
# MAX_MATCH_SAMPLES_PER_FINDING already makes for the tenant, and 50 matches it so the
# local file and the yara_match row show the same sample.
#
# The complete list is never lost: the matched file is still on the host (the scanner never
# quarantines, moves or deletes), so `yara -s <rules> "<path>"` regenerates every offset.
# 0 disables the cap and restores the old render-everything behaviour.
MAX_ALERT_OFFSETS_PER_FINDING = _env_number("YARA_MAX_ALERT_OFFSETS", 50, cast=int)
MAX_ALERT_OFFSETS_PER_FINDING = max(0, MAX_ALERT_OFFSETS_PER_FINDING)

YARA_RULE = r""""""


# ============================================================================
# CLEANUP SCRIPTS
# ============================================================================

b64CleanupScriptWindows = (
    "CkBlY2hvIG9mZgpjZCAvZCBjOlx4ZHItZGF0YVxhbGVydApyZW4gKi50eHQgKi5hbGVydAo="
)
b64CleanupScriptLinux = "IyEvYmluL2Jhc2gKY2QgL29wdC94ZHItZGF0YS9hbGVydApmb3IgZmlsZSBpbiAqLnR4dDsgZG8KICAgIG12ICIkZmlsZSIgIiR7ZmlsZSUudHh0fS5hbGVydCIKZG9uZQ=="



# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_os_info():
    """Get human-readable OS information including version and architecture."""
    system = platform.system()
    release = platform.release()
    machine = platform.machine()

    if system == "Darwin":
        major = release.split('.')[0]
        mac_names = {
            '24': 'macOS 15 (Sequoia)',
            '23': 'macOS 14 (Sonoma)',
            '22': 'macOS 13 (Ventura)',
            '21': 'macOS 12 (Monterey)',
        }
        name = mac_names.get(major, f'macOS (Darwin {release})')
        return f"{name} [{machine}]"
    elif system == "Linux":
        return f"Linux {release} [{machine}]"
    elif system == "Windows":
        return f"Windows {release} [{machine}]"
    return f"{system} {release} [{machine}]"


def get_system_info():
    """Get system hostname, IP addresses, and OS info."""
    hostname = socket.gethostname()
    os_info = get_os_info()
    
    try:
        ip_addresses = []
        for interface in socket.getaddrinfo(hostname, None):
            ip = interface[4][0]
            if ip not in ip_addresses and not ip.startswith("127."):
                ip_addresses.append(ip)
        return hostname, ip_addresses, os_info
    except Exception as e:
        return hostname, ["Unable to determine IP address: " + str(e)], os_info


def _ensure_text(obj):
    """Convert bytes to text with fallback encoding."""
    if isinstance(obj, bytes):
        for enc in ("utf-8", "latin-1"):
            try:
                return obj.decode(enc)
            except UnicodeDecodeError:
                pass
        return obj.decode("utf-8", "replace")
    return obj if isinstance(obj, str) else str(obj)


def _b64_to_text(s: str) -> str:
    """Decode base64 string to UTF-8 text."""
    s = _ensure_text(s).strip()
    if s.lower().startswith("b64:"):
        s = s[4:]
    s = s.replace("\n", "").replace("\r", "").replace(" ", "")
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        raw = base64.b64decode(s)
        return _ensure_text(raw)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")


def _iter_yara_top_level_words(source_text):
    """Yield top-level YARA word tokens while ignoring strings and comments."""
    text = _ensure_text(source_text or "")
    i = 0
    text_len = len(text)
    brace_depth = 0
    in_string = False
    in_line_comment = False
    in_block_comment = False

    while i < text_len:
        ch = text[i]

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and i + 1 < text_len and text[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            if ch == "\\" and i + 1 < text_len:
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue

        if ch == "/" and i + 1 < text_len:
            next_ch = text[i + 1]
            if next_ch == "/":
                in_line_comment = True
                i += 2
                continue
            if next_ch == "*":
                in_block_comment = True
                i += 2
                continue

        if ch == '"':
            in_string = True
            i += 1
            continue

        if ch == "{":
            brace_depth += 1
            i += 1
            continue

        if ch == "}":
            if brace_depth > 0:
                brace_depth -= 1
            i += 1
            continue

        if brace_depth == 0 and (ch.isalpha() or ch == "_"):
            start = i
            i += 1
            while i < text_len and (text[i].isalnum() or text[i] == "_"):
                i += 1
            word = text[start:i]
            yield word.lower(), start, i, word
            continue

        i += 1


def _get_yara_top_level_statements(source_text):
    """Return top-level YARA statements in source order."""
    text = _ensure_text(source_text or "")
    tokens = list(_iter_yara_top_level_words(text))
    statements = []
    modifier_start = None

    for idx, (lowered, start, _end, word) in enumerate(tokens):
        if lowered in ("private", "global"):
            if modifier_start is None:
                modifier_start = start
            continue

        if lowered == "rule":
            rule_name = None
            if idx + 1 < len(tokens):
                next_word = tokens[idx + 1][3]
                if re.match(r"^[A-Za-z_]\w*$", next_word):
                    rule_name = next_word

            statements.append({
                "type": "rule",
                "start": modifier_start if modifier_start is not None else start,
                "keyword_start": start,
                "name": rule_name,
            })
            modifier_start = None
            continue

        if lowered in ("import", "include"):
            statements.append({
                "type": lowered,
                "start": start,
                "keyword_start": start,
                "name": None,
            })

        modifier_start = None

    statements.sort(key=lambda item: item["start"])

    for idx, statement in enumerate(statements):
        next_start = statements[idx + 1]["start"] if idx + 1 < len(statements) else len(text)
        statement["end"] = next_start
        statement["text"] = text[statement["start"]:next_start].strip()

    return statements


def _build_yara_rule_source_map(source_text):
    """Map rule names to their original source text."""
    rule_map = {}
    for statement in _get_yara_top_level_statements(source_text):
        if statement["type"] != "rule":
            continue
        rule_name = statement.get("name")
        if rule_name:
            rule_map[rule_name.lower()] = statement["text"]
    return rule_map


def _summarize_condition_only_match(rule_name, meta=None, tags=None, rule_source=None):
    """Build a human-readable fallback explanation for condition-only matches."""
    meta = meta or {}
    tags = tags or []
    summary_parts = ["Condition-only YARA match; no string instances were produced."]

    purpose = str(meta.get("purpose", "") or "").strip()
    severity = str(meta.get("severity", "") or "").strip()
    scope = str(meta.get("scope", "") or "").strip()
    author = str(meta.get("author", "") or "").strip()

    if purpose:
        summary_parts.append(f"Purpose: {purpose}.")
    if severity:
        summary_parts.append(f"Severity: {severity}.")
    if scope:
        summary_parts.append(f"Scope: {scope}.")
    if author:
        summary_parts.append(f"Author: {author}.")
    if tags:
        summary_parts.append(f"Tags: {', '.join(str(tag) for tag in tags)}.")

    if rule_source:
        condition_notes = []
        if re.search(r'uint16\s*\(\s*0\s*\)\s*==\s*0x5A4D', rule_source, re.IGNORECASE):
            condition_notes.append("checks for an MZ/PE header")

        imported_functions = []
        seen_functions = set()
        for func_name in re.findall(r'pe\.imports\(\s*"[^"]+"\s*,\s*"([^"]+)"\s*\)', rule_source, re.IGNORECASE):
            if func_name not in seen_functions:
                seen_functions.add(func_name)
                imported_functions.append(func_name)

        if imported_functions:
            condition_notes.append("references imports: " + ", ".join(imported_functions))

        if re.search(r'\bpe\.', rule_source):
            condition_notes.append("uses the PE module for structural checks")

        if condition_notes:
            summary_parts.append("Condition evidence: " + "; ".join(condition_notes) + ".")

    summary_parts.append(f"Rule: {rule_name}.")
    return " ".join(summary_parts)


def decode_yara_rules(encoded_b64: str, error_logger=None) -> str:
    """
    Decode and validate YARA rules from base64.
    
    Args:
        encoded_b64: Base64 encoded YARA rules
        error_logger: Optional error logger instance
        
    Returns:
        Decoded YARA rules text
        
    Raises:
        ValueError: If decoding fails or content is invalid
    """
    if len(encoded_b64) > 50_000_000:
        raise ValueError("YARA rules input too large")
    
    if not encoded_b64 or not _ensure_text(encoded_b64).strip():
        error_msg = "Empty YARA rules content provided"
        if error_logger:
            error_logger.has_errors = True
            error_logger.error_logger.error(f"INPUT_ERROR: {error_msg}")
        raise ValueError(error_msg)

    try:
        text = _b64_to_text(encoded_b64)
    except Exception as e:
        error_msg = f"Base64 decode failed: {e}"
        if error_logger:
            error_logger.has_errors = True
            error_logger.error_logger.error(f"DECODE_ERROR: {error_msg}")
        raise ValueError(error_msg)

    rules_found = [
        statement for statement in _get_yara_top_level_statements(text)
        if statement["type"] == "rule"
    ]
    
    if not rules_found:
        error_msg = "Decoded content does not contain any YARA 'rule' declarations"
        if error_logger:
            error_logger.has_errors = True
            error_logger.error_logger.error(f"VALIDATION_ERROR: {error_msg}")
        raise ValueError(error_msg)
    
    return text


def _is_case_sensitive_fs():
    """Detect if the filesystem is case-sensitive."""
    if platform.system() == "Windows":
        return False
    elif platform.system() == "Darwin":
        test_file = f"/tmp/CaSe_TeSt_YaRa_{os.getpid()}"
        try:
            with open(test_file, 'w') as f:
                f.write("test")
            exists_lower = os.path.exists(test_file.lower())
            os.remove(test_file)
            return not exists_lower
        except:
            return False
    else:
        return True


def _is_junction_or_symlink(path):
    """Check if path is a junction point or symbolic link."""
    if platform.system() != "Windows":
        return os.path.islink(path)
    
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
        if attrs == -1:
            return False
        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False


def _get_real_path(path):
    """Get real path resolving junctions/symlinks with case normalization."""
    try:
        real_path = os.path.realpath(path)
        if platform.system() == "Windows":
            return os.path.normpath(real_path).lower()
        elif platform.system() == "Darwin":
            if not _is_case_sensitive_fs():
                return os.path.normpath(real_path).lower()
            else:
                return os.path.normpath(real_path)
        else:
            return os.path.normpath(real_path)
    except Exception:
        if platform.system() == "Windows":
            return os.path.normpath(path).lower()
        elif platform.system() == "Darwin":
            if not _is_case_sensitive_fs():
                return os.path.normpath(path).lower()
            else:
                return os.path.normpath(path)
        else:
            return os.path.normpath(path)


def _should_skip_junction(path):
    """Check if junction/symlink should be skipped to avoid loops."""
    if not _is_junction_or_symlink(path):
        return False
    
    if platform.system() == "Windows":
        path_lower = path.lower()
        problematic_junctions = [
            'documents and settings', 'application data', 'local settings',
            'my documents', 'default user', 'all users'
        ]
        return any(junction in path_lower for junction in problematic_junctions)
    elif platform.system() == "Darwin":
        macos_skip_symlinks = ['/etc', '/tmp', '/var']
        return any(path.startswith(symlink) for symlink in macos_skip_symlinks)
    else:
        linux_skip_symlinks = ['/proc/self/fd', '/proc/self/task']
        return any(path.startswith(symlink) for symlink in linux_skip_symlinks)


def _exp_backoff_delay(attempt_index):
    """Calculate exponential backoff delay with jitter."""
    raw = BASE_BACKOFF_SECS * (2 ** (attempt_index - 1))
    if raw > MAX_BACKOFF_SECS:
        raw = MAX_BACKOFF_SECS
    return raw * random.uniform(0.5, 1.0)


def _collect_batch(queue_obj, first_item, max_events=None, max_bytes=None):
    """Drain up to a batch's worth of already-queued items, starting from first_item.

    Non-blocking after the first item: whatever is sitting in the queue right now is
    taken, up to the event/byte cap. It never waits for the queue to fill, so a quiet
    scan still delivers promptly - the caller already blocked to get first_item.

    Returns (items, saw_sentinel). saw_sentinel is True if the None shutdown marker was
    pulled, so the caller can send this final batch and then exit.
    """
    max_events = max_events or UPLOAD_BATCH_MAX_EVENTS
    max_bytes = max_bytes or UPLOAD_BATCH_MAX_BYTES
    items = [first_item]
    approx = 0
    saw_sentinel = False
    while len(items) < max_events and approx < max_bytes:
        try:
            nxt = queue_obj.get_nowait()
        except Empty:
            break
        if nxt is None:
            saw_sentinel = True
            break
        items.append(nxt)
        try:
            approx += len(json.dumps(nxt.to_dict(), ensure_ascii=False))
        except Exception:
            approx += 1024
    return items, saw_sentinel


def _ndjson_body(items):
    """Serialize StandardLogEntry items as NDJSON - one JSON object per line.

    This is the ONLY multi-event format the HTTP Collector actually ingests. A JSON
    array is answered with HTTP 200 {"error":"false"} and then silently discarded, so
    getting this wrong loses data with no error anywhere. Verified against the tenant.
    """
    return "\n".join(json.dumps(i.to_dict(), ensure_ascii=False) for i in items)


def _post_ndjson(endpoint, api_key, items, timeout=None):
    """POST a batch of events as NDJSON. Returns the requests Response."""
    return requests.post(
        url=endpoint,
        headers={"Authorization": api_key, "Content-Type": "text/plain"},
        data=_ndjson_body(items).encode("utf-8"),
        timeout=timeout or DEFAULT_TIMEOUT_SECS,
    )


def _get_webhook_endpoint(api_endpoint: str) -> str:
    """Return the configured webhook endpoint, normalized for requests."""
    return (api_endpoint or "").strip()


def _default_scanner_dir():
    """Platform default scanner working directory (must match ScanConfig's choice)."""
    override = os.environ.get("YARA_SCANNER_DIR")
    if override and override.strip():
        return override.strip()
    if platform.system() == "Windows":
        return "C:\\yara_scanner"
    if platform.system() == "Darwin":
        return "/usr/local/yara_scanner"
    return "/opt/yara_scanner"


def _handle_cancel_request():
    """mode=cancel: drop a cooperative cancel flag for a running scan on this endpoint.

    Deliberately lightweight - does NOT initialize the logging/scan machinery, compile
    rules, or touch the collector. Writes <scanner_dir>/control/cancel.flag and reports
    whether a scan appears alive via the running.json marker an active scan refreshes.

    This is the supported alternative to the console's Cancel button, which hard-kills the
    payload process: findings already queued are lost, no summary is written, and the scan
    simply vanishes. A cooperative cancel unwinds the scan, drains what it has, and writes
    its scan_summary_<run_id>.json.
    """
    scanner_dir = _default_scanner_dir()
    control_dir = os.path.join(scanner_dir, "control")
    try:
        os.makedirs(control_dir, exist_ok=True)
    except Exception as e:
        return f"Cancel failed: cannot create control dir {control_dir}: {e}"

    flag_path = os.path.join(control_dir, "cancel.flag")
    running_path = os.path.join(control_dir, "running.json")

    running = False
    running_info = {}
    try:
        if os.path.exists(running_path):
            with open(running_path, "r", encoding="utf-8") as f:
                running_info = json.load(f) or {}
            updated = float(running_info.get("updated_at", 0))
            running = (time.time() - updated) < RUNNING_MARKER_STALE_SECS
    except Exception:
        running = False

    try:
        with open(flag_path, "w", encoding="utf-8") as f:
            json.dump({
                "requested_at_ms": int(time.time() * 1000),
                "source": "action_center",
            }, f)
    except Exception as e:
        return f"Cancel failed: cannot write {flag_path}: {e}"

    return (
        f"Cancel signal delivered ({flag_path}) | scanner running: "
        f"{'yes' if running else 'no'} | scan_id={running_info.get('scan_id', 'n/a')}"
    )




def _parse_alert_severity(value, arg_name="alert_severity"):
    """Parse and validate alert severity."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("low", "medium", "high"):
        return text
    raise ValueError(f"Invalid {arg_name} '{value}'. Use low, medium, or high.")


YARA_COMPILE_EXTERNALS = {
    # Some community rules reference external vars in conditions.
    "filepath": "",
    "filepath_lower": "",
    "filename": "",
    "filename_lower": "",
}


def _build_yara_match_externals(file_path):
    """Build per-file external values available to YARA rule conditions."""
    normalized_path = os.path.normpath(_ensure_text(file_path or ""))
    filename = os.path.basename(normalized_path)
    return {
        "filepath": normalized_path,
        "filepath_lower": normalized_path.lower(),
        "filename": filename,
        "filename_lower": filename.lower(),
    }




def _normalize_match_strings(raw_strings):
    """Normalize YARA string matches into (offset, string_id, data) tuples."""
    normalized = []
    for item in raw_strings:
        if isinstance(item, (tuple, list)) and len(item) == 3:
            off, sid, data = item
            normalized.append((int(off), str(sid), data))
            continue

        if hasattr(item, "identifier") and hasattr(item, "instances"):
            sid = str(getattr(item, "identifier", "unknown"))
            for inst in (getattr(item, "instances", []) or []):
                off = int(getattr(inst, "offset", -1))
                data = getattr(inst, "matched_data", b"")
                normalized.append((off, sid, data))
            continue

        off = int(getattr(item, "offset", -1)) if hasattr(item, "offset") else -1
        sid = str(getattr(item, "identifier", "unknown"))
        data = getattr(item, "matched_data", getattr(item, "data", b""))
        normalized.append((off, sid, data))

    return normalized


def _sha256_file(path, chunk_size=1024*1024):
    """Calculate SHA256 hash of file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _get_file_creation_time_iso(path, stat_result=None):
    """
    Best-effort file creation time in ISO format.
    On platforms without true birth time, returns None.
    """
    try:
        st = stat_result or os.stat(path)

        if platform.system() == "Windows":
            return datetime.datetime.fromtimestamp(st.st_ctime, tz=datetime.timezone.utc).isoformat()

        if hasattr(st, "st_birthtime"):
            return datetime.datetime.fromtimestamp(st.st_birthtime, tz=datetime.timezone.utc).isoformat()
    except Exception:
        return None


def _apply_light_process_priority(log_manager=None):
    """Best-effort priority tuning so user activity wins on busy machines."""
    details = {}
    try:
        process = psutil.Process()

        if platform.system() == "Windows":
            try:
                process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                details["cpu_priority"] = "below_normal"
            except Exception as e:
                details["cpu_priority_error"] = str(e)
        else:
            try:
                current_nice = process.nice()
                target_nice = max(int(current_nice), 10)
                process.nice(target_nice)
                details["cpu_priority"] = f"nice={target_nice}"
            except Exception as e:
                details["cpu_priority_error"] = str(e)

            if platform.system() == "Linux" and hasattr(process, "ionice"):
                try:
                    process.ionice(psutil.IOPRIO_CLASS_BE, 7)
                    details["io_priority"] = "best_effort:7"
                except Exception as e:
                    details["io_priority_error"] = str(e)

        if log_manager:
            log_manager.log_system("Applied light profile process priority tuning", details)
    except Exception as e:
        if log_manager:
            log_manager.log_system(f"Could not apply light profile process priority tuning: {e}")

    return None


def _scan_error_reason(exc):
    """Bounded skip_reasons key for a per-file scan error.

    skip_reasons is an AGGREGATE breakdown - its keys are labels, and the whole dict is
    serialised into the final report and a statistics event. Returning str(exc) made every
    errored file its own key, because both common error texts embed the absolute path
    (yara.Error is 'could not open file "<path>"', OSError is '[Errno 2] ...: <path>').
    On a full-system scan, where files vanish or lock between the access check and
    rules.match routinely, that is unbounded growth shipped to the tenant - measured at
    307,780 bytes for 5,000 errored files.

    The exception TYPE is kept so genuinely different failures stay distinguishable, and
    "error" stays in the label because the final report counts error reasons by that
    substring. The specific message and path are not lost: scan_file logs them per file.
    """
    return f"Scan error ({type(exc).__name__})"


def _render_match_data(data) -> str:
    """Render YARA-matched bytes as a printable string for human-readable output.

    YARA wide-string matches return UTF-16 LE bytes (e.g. b'N\\x00o\\x00...');
    decoding those as UTF-8 leaves embedded NUL bytes in the output and breaks
    editors like Notepad. Decode UTF-16 LE when the byte pattern looks wide,
    fall back to UTF-8 for ASCII matches, and to hex for binary blobs.
    """
    if not isinstance(data, (bytes, bytearray)):
        return str(data)
    if len(data) >= 2 and len(data) % 2 == 0 and all(b == 0 for b in data[1::2]):
        try:
            decoded = data.decode("utf-16-le")
            if all(c.isprintable() or c == "\t" for c in decoded):
                return decoded
        except Exception:
            pass
    try:
        decoded = data.decode("utf-8")
        if all(c.isprintable() or c == "\t" for c in decoded):
            return decoded
    except Exception:
        pass
    return data.hex()


def _iter_hit_fields(hit):
    """Extract fields from YARA match (cached dict or live Match object)."""
    if isinstance(hit, dict):
        rule = hit.get("rule")
        tags = hit.get("tags", [])
        meta = hit.get("meta", {})
        strings = []
        for (o, sid, hx) in hit.get("strings", []):
            try:
                data = bytes.fromhex(hx)
            except Exception:
                data = hx.encode("utf-8", errors="ignore")
            strings.append((o, sid, data))
        return rule, tags, meta, strings
    else:
        strings = _normalize_match_strings(list(getattr(hit, "strings", []) or []))
        return hit.rule, list(getattr(hit, "tags", []) or []), dict(getattr(hit, "meta", {}) or []), strings


# ============================================================================
# LOG TYPE ENUM
# ============================================================================

class LogType(Enum):
    """Log entry types for categorized logging."""
    ALERT = "alert"
    STATISTICS = "statistics"
    ERROR = "error"
    PERFORMANCE = "performance"
    UPLOAD = "upload"
    SYSTEM = "system"


# ============================================================================
# STANDARDIZED DATA STRUCTURES
# ============================================================================

class StandardLogEntry:
    """Standardized log entry for consistent webhook uploads."""
    
    def __init__(self, log_type, hostname, os_info, ip_address, scan_id, message=None, level="INFO", data=None):
        current_time = time.time()
        
        self.type = log_type
        self.hostname = hostname
        self.os_info = os_info
        self.ipAddress = ip_address
        self.timestamp = current_time
        self.scan_id = scan_id
        self.timestamp_iso = datetime.datetime.fromtimestamp(current_time, tz=datetime.timezone.utc).isoformat()
        self.uploader_version = "enhanced_v2"
        self.source = "yara_scanner"
        
        if message:
            self.message = message
        if level:
            self.level = level
        if data:
            self.data = data
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        result = {
            "type": self.type,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "ipAddress": self.ipAddress,
            "timestamp": self.timestamp,
            "timestamp_iso": self.timestamp_iso,
            "scan_id": self.scan_id,
            "uploader_version": self.uploader_version,
            "source": self.source
        }
        
        if hasattr(self, 'message'):
            result['message'] = self.message
        if hasattr(self, 'level'):
            result['level'] = self.level
        if hasattr(self, 'data'):
            result['data'] = self.data
            
        return result
    


def create_standard_log(log_type, hostname, os_info, ip_address, scan_id, message=None, level="INFO", data=None):
    """Factory function for creating standardized log entries."""
    return StandardLogEntry(log_type, hostname, os_info, ip_address, scan_id, message, level, data)


class PerformanceSnapshot:
    """Snapshot of system performance metrics at a point in time."""
    
    def __init__(self, timestamp, cpu_percent, memory_mb, memory_percent, 
                 disk_io_read_mb, disk_io_write_mb, network_sent_mb, network_recv_mb,
                 files_scanned, detections_found, queue_size, active_workers):
        self.timestamp = timestamp
        self.cpu_percent = cpu_percent
        self.memory_mb = memory_mb
        self.memory_percent = memory_percent
        self.disk_io_read_mb = disk_io_read_mb
        self.disk_io_write_mb = disk_io_write_mb
        self.network_sent_mb = network_sent_mb
        self.network_recv_mb = network_recv_mb
        self.files_scanned = files_scanned
        self.detections_found = detections_found
        self.queue_size = queue_size
        self.active_workers = active_workers
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'cpu_percent': self.cpu_percent,
            'memory_mb': self.memory_mb,
            'memory_percent': self.memory_percent,
            'disk_io_read_mb': self.disk_io_read_mb,
            'disk_io_write_mb': self.disk_io_write_mb,
            'network_sent_mb': self.network_sent_mb,
            'network_recv_mb': self.network_recv_mb,
            'files_scanned': self.files_scanned,
            'detections_found': self.detections_found,
            'queue_size': self.queue_size,
            'active_workers': self.active_workers
        }


# ============================================================================
# HELPER CLASSES
# ============================================================================

class CircuitBreaker:
    """Circuit breaker pattern for resilient webhook uploads."""
    
    def __init__(self, failure_threshold=CIRCUIT_FAILURE_THRESHOLD, reset_timeout=CIRCUIT_RESET_TIMEOUT_SECS):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.consecutive_failures = 0
        self.state = "closed"
        self.opened_at = None
        self._lock = threading.Lock()

    def allow(self):
        """Check if request should be allowed through."""
        with self._lock:
            if self.state == "open":
                if (time.time() - (self.opened_at or 0)) >= self.reset_timeout:
                    self.state = "half_open"
                    return True
                return False
            return True

    def on_success(self):
        """Record successful request."""
        with self._lock:
            self.consecutive_failures = 0
            self.state = "closed"
            self.opened_at = None

    def on_failure(self):
        """Record failed request."""
        with self._lock:
            self.consecutive_failures += 1
            if self.state == "half_open":
                self.state = "open"
                self.opened_at = time.time()
            elif self.consecutive_failures >= self.failure_threshold:
                self.state = "open"
                self.opened_at = time.time()


class FileHasher:
    """Utility for calculating file hashes."""
    
    @staticmethod
    def calculate_sha256(file_path):
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {e}")
            return None


# ============================================================================
# ROADMAP FEATURES (Caching)
# ============================================================================

# Roadmap Feature: Caching implementation (currently disabled/dormant)


# ============================================================================
# LOGGING & MONITORING SYSTEM
# ============================================================================

class ErrorLogger:
    """Dedicated logger for the YARA processing audit trail (rule compilation summary, module list, and any errors)."""

    def __init__(self, config):
        self.config = config
        self.error_log_file = os.path.join(
            self.config.logs_dir, f"yara_processing_{self.config.run_id}.log"
        )
        self.error_logger = self._setup_error_logger()
        self.has_errors = False
        self.failed_rules_count = 0
        self.valid_rules_count = 0
        # Rules the agent's libyara cannot run (module unavailable) rather than rules that
        # are broken. Counted separately so the operator-visible result can say so: without
        # it, reclassifying these out of failed_rules_count makes them vanish entirely and
        # a pack where most rules never ran reads as a clean "0 rules failed compilation".
        self.skipped_rules_count = 0
    
    def _setup_error_logger(self):
        """Setup dedicated error logger."""
        logger_name = f"error_logger_{id(self)}"
        error_logger = logging.getLogger(logger_name)
        error_logger.setLevel(logging.INFO)
        
        for handler in error_logger.handlers[:]:
            handler.close()
            error_logger.removeHandler(handler)
        
        try:
            error_handler = logging.FileHandler(
                self.error_log_file, 
                encoding="utf-8", 
                mode="w"
            )
            error_handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            error_handler.setFormatter(formatter)
            
            error_logger.addHandler(error_handler)
            error_logger.propagate = False
            
            error_logger.info("=== YARA Processing Log ===")
            error_logger.info(f"Python Version: {sys.version}")
            error_logger.info(f"Platform: {platform.platform()}")
            error_logger.info(f"YARA Version: {yara.__version__ if hasattr(yara, '__version__') else 'Unknown'}")
            error_logger.info("=" * 50)
            
        except Exception as e:
            print(f"Failed to setup error logger: {e}")
            return logging.getLogger()
        
        return error_logger
    
    def _analyze_compilation_error(self, error_msg, rule_content, error_line_num):
        """Analyze compilation error and provide diagnostics."""
        analysis = {
            'error_category': 'unknown',
            'suggestions': [],
            'severity': 'medium'
        }
        
        error_str = str(error_msg).lower()
        
        if "invalid field name" in error_str:
            analysis['error_category'] = 'invalid_pe_field'
            analysis['severity'] = 'high'
            analysis['suggestions'] = [
                'Check PE module field names against YARA documentation',
                'Common valid fields: pe.is_pe, pe.imphash(), pe.machine, pe.timestamp'
            ]
            field_match = re.search(r'invalid field name "([^"]+)"', str(error_msg))
            if field_match:
                analysis['invalid_field'] = field_match.group(1)
                
        elif "syntax error" in error_str:
            analysis['error_category'] = 'syntax_error'
            analysis['severity'] = 'high'
            analysis['suggestions'] = [
                'Check for missing brackets, braces, or quotes',
                'Verify condition syntax',
                'Check string declarations'
            ]
            if "unexpected" in error_str:
                unexpected_match = re.search(r'unexpected (.+)', str(error_msg))
                if unexpected_match:
                    analysis['unexpected_token'] = unexpected_match.group(1)
                    
        elif "undefined identifier" in error_str:
            analysis['error_category'] = 'undefined_identifier'
            analysis['severity'] = 'medium'
            analysis['suggestions'] = [
                'Check variable names in condition',
                'Verify string identifiers are defined',
                'Check for typos in identifiers'
            ]
            
        elif "duplicated" in error_str:
            analysis['error_category'] = 'duplicate_definition'
            analysis['severity'] = 'low'
            analysis['suggestions'] = [
                'Remove duplicate rule names',
                'Check for duplicate string identifiers'
            ]
        
        if error_line_num and rule_content:
            lines = rule_content.split('\n')
            if error_line_num <= len(lines):
                problematic_line = lines[error_line_num - 1] if error_line_num > 0 else ""
                analysis['problematic_line'] = problematic_line.strip()
                analysis['line_analysis'] = {
                    'contains_condition': 'condition:' in problematic_line.lower(),
                    'contains_strings': 'strings:' in problematic_line.lower(),
                    'contains_meta': 'meta:' in problematic_line.lower(),
                    'line_length': len(problematic_line),
                    'indentation_spaces': len(problematic_line) - len(problematic_line.lstrip())
                }
        
        return analysis

    def log_rule_compilation_error(self, rule_name, rule_content, error_msg):
        """Log detailed rule compilation error."""
        self.has_errors = True
        self.failed_rules_count += 1
        
        self.error_logger.error(f"=== RULE COMPILATION FAILURE #{self.failed_rules_count} ===")
        self.error_logger.error(f"Rule Name: {rule_name}")
        self.error_logger.error(f"Error: {error_msg}")
        self.error_logger.error(f"Error Type: {type(error_msg).__name__}")
        
        error_line_num = None
        try:
            line_match = re.search(r'line (\d+)', str(error_msg))
            if line_match:
                error_line_num = int(line_match.group(1))
        except Exception:
            pass
        
        self.error_logger.error("Failed Rule Content:")
        self.error_logger.error("-" * 40)
        
        lines = rule_content.split('\n')
        for i, line in enumerate(lines, 1):
            if error_line_num and i == error_line_num:
                self.error_logger.error(f"{i:3d}: {line} <-- ERROR HERE")
            else:
                self.error_logger.error(f"{i:3d}: {line}")
        
        self.error_logger.error("-" * 40)
                
        error_analysis = self._analyze_compilation_error(error_msg, rule_content, error_line_num)
        
        if hasattr(self.config, 'log_manager') and self.config.log_manager:
            error_data = {
                'rule_name': rule_name,
                'error_message': str(error_msg),
                'error_type': type(error_msg).__name__,
                'error_line_number': error_line_num,
                'rule_length_lines': len(lines),
                'error_analysis': error_analysis,
                'compilation_failure_number': self.failed_rules_count
            }
            self.config.log_manager.log_error(
                f"YARA rule compilation failed: {rule_name}",
                error_data
            )
        
        self.error_logger.error("=" * 50)
  
    def log_compilation_summary(self):
        """Log final compilation summary."""
        total_rules = self.valid_rules_count + self.failed_rules_count
        self.error_logger.info("=" * 50)
        self.error_logger.info("COMPILATION SUMMARY")
        self.error_logger.info("=" * 50)
        self.error_logger.info(f"Total rules processed: {total_rules}")
        self.error_logger.info(f"Valid rules compiled: {self.valid_rules_count}")
        self.error_logger.info(f"Failed rules skipped: {self.failed_rules_count}")
        
        if total_rules > 0:
            success_rate = (self.valid_rules_count / total_rules) * 100
            self.error_logger.info(f"Success rate: {success_rate:.1f}%")
        
        if self.failed_rules_count > 0:
            self.error_logger.info(f"Failed rules saved to: {self.config.failed_rules_dir}")
        
        self.error_logger.info("=" * 50)


class ExceptionLogger:
    """Lazy logger for script-level exceptions.

    The log file is only created on the first call to log_exception(), so
    clean runs leave no zero-byte file in the logs directory.
    """

    def __init__(self, config):
        self.config = config
        self.exception_log_file = os.path.join(
            self.config.logs_dir, f"script_exceptions_{self.config.run_id}.log"
        )
        self.exception_logger = None
        self.exception_count = 0

    def _ensure_logger(self):
        """Lazily create the file handler and write the init banner."""
        if self.exception_logger is not None:
            return self.exception_logger

        logger_name = f"exception_logger_{id(self)}"
        exception_logger = logging.getLogger(logger_name)
        exception_logger.setLevel(logging.ERROR)

        for handler in exception_logger.handlers[:]:
            handler.close()
            exception_logger.removeHandler(handler)

        try:
            exception_handler = logging.FileHandler(
                self.exception_log_file,
                encoding="utf-8",
                mode="w"
            )
            exception_handler.setLevel(logging.ERROR)

            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] [EXCEPTION] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            exception_handler.setFormatter(formatter)
            exception_logger.addHandler(exception_handler)
            exception_logger.propagate = False

            exception_logger.error("=== SCRIPT EXCEPTION LOG INITIALIZED ===")
            exception_logger.error(f"Python Version: {sys.version}")
            exception_logger.error(f"Platform: {platform.platform()}")
            exception_logger.error("=" * 60)

        except Exception as e:
            print(f"Failed to setup exception logger: {e}")
            exception_logger = logging.getLogger()

        self.exception_logger = exception_logger
        return exception_logger

    def log_exception(self, exception, context="Unknown", additional_info=None):
        """Log detailed exception information."""
        self.exception_count += 1
        logger = self._ensure_logger()

        logger.error(f"=== EXCEPTION #{self.exception_count} ===")
        logger.error(f"Context: {context}")
        logger.error(f"Exception Type: {type(exception).__name__}")
        logger.error(f"Exception Message: {str(exception)}")

        if additional_info:
            logger.error(f"Additional Info: {additional_info}")

        logger.error("Full Traceback:")
        logger.error(traceback.format_exc())
        logger.error("=" * 60)



class StatisticsManager:
    """Manager for comprehensive scan statistics and performance monitoring."""
    
    def __init__(self, config, log_manager=None):
        self.config = config
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"

        self.log_manager = log_manager
        self.stats_logger = None
        self.performance_logger = None
        self.process = None
        self.initial_io_counters = None
        self.initial_net_counters = None
        self.monitoring_thread = None

        self.performance_history = deque(maxlen=1000)
        self.worker_stats = defaultdict(lambda: {
            'files_processed': 0,
            'processing_time': 0.0,
            'errors': 0,
            'last_activity': 0
        })
                
        self.scan_estimates = {
            'total_files_estimate': 0,
            'completion_estimate': None,
            'current_rate': 0.0,
            'average_rate': 0.0,
            'eta_seconds': None
        }
        
        self.performance_metrics = {
            'peak_cpu_percent': 0.0,
            'peak_memory_mb': 0.0,
            'avg_cpu_percent': 0.0,
            'avg_memory_mb': 0.0,
            'io_efficiency': 0.0
        }
        
        self.lock_stats = threading.Lock()
        self.lock_performance = threading.Lock()
        self.monitoring_active = True
        self._stopped = False
        
        if self.log_manager is not None:
            self.stats_logger = self.log_manager.loggers[LogType.STATISTICS]
            self.performance_logger = self.log_manager.loggers[LogType.PERFORMANCE]
        else:
            self.stats_logger = logging.getLogger()
            self.performance_logger = logging.getLogger()
        
        try:
            self.process = psutil.Process()
            
            if platform.system() == "Darwin":
                self.initial_io_counters = None
            else:
                try:
                    self.initial_io_counters = self.process.io_counters()
                except:
                    self.initial_io_counters = None
            
            try:
                self.initial_net_counters = psutil.net_io_counters()
            except:
                self.initial_net_counters = None

            if self.stats_logger:
                self.stats_logger.info("=== Statistics Manager Initialized ===")
            if self.performance_logger:
                self.performance_logger.info("=== Performance Monitoring Started ===")
                
        except ImportError:
            logging.error("psutil not available - performance monitoring will be limited")
            if self.stats_logger:
                self.stats_logger.error("psutil not available - performance monitoring limited")
        except Exception as e:
            logging.error(f"Failed to initialize process monitoring: {e}")
            if self.stats_logger:
                self.stats_logger.error(f"Failed to initialize process monitoring: {e}")
        
        try:
            self.start_monitoring()
        except Exception as e:
            logging.error(f"Failed to start performance monitoring: {e}")
            if self.stats_logger:
                self.stats_logger.error(f"Failed to start performance monitoring: {e}")

    def start_monitoring(self):
        """Start background performance monitoring thread."""
        if not getattr(self.config, "enable_performance_monitoring", True):
            self.stats_logger.info("Performance monitoring disabled in light profile")
            return
        if not self.monitoring_thread or not self.monitoring_thread.is_alive():
            self.monitoring_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
            self.monitoring_thread.start()
            self.stats_logger.info("Performance monitoring thread started")

    def _monitoring_worker(self):
        """Background worker collecting performance metrics."""
        self.performance_logger.info("Performance monitoring worker started")
        
        while self.monitoring_active:
            try:
                snapshot = self._collect_performance_snapshot()
                
                with self.lock_performance:
                    self.performance_history.append(snapshot)
                    self._update_performance_metrics(snapshot)
                
                if len(self.performance_history) % 6 == 0:
                    self._log_performance_details(snapshot)
                
                time.sleep(5)
                
            except Exception as e:
                self.performance_logger.error(f"Monitoring error: {e}")
                time.sleep(10)
        
        self.performance_logger.info("Performance monitoring worker stopped")

    def _collect_performance_snapshot(self):
        """Collect current system metrics."""
        try:
            cpu_percent = self.process.cpu_percent()
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            memory_percent = self.process.memory_percent()
            
            if self.initial_io_counters is not None and platform.system() != "Darwin":
                try:
                    io_counters = self.process.io_counters()
                    disk_read_mb = (io_counters.read_bytes - self.initial_io_counters.read_bytes) / 1024 / 1024
                    disk_write_mb = (io_counters.write_bytes - self.initial_io_counters.write_bytes) / 1024 / 1024
                except:
                    disk_read_mb = 0
                    disk_write_mb = 0
            else:
                disk_read_mb = 0
                disk_write_mb = 0

            net_counters = psutil.net_io_counters()
            net_sent_mb = (net_counters.bytes_sent - self.initial_net_counters.bytes_sent) / 1024 / 1024
            net_recv_mb = (net_counters.bytes_recv - self.initial_net_counters.bytes_recv) / 1024 / 1024
            
            return PerformanceSnapshot(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                memory_percent=memory_percent,
                disk_io_read_mb=disk_read_mb,
                disk_io_write_mb=disk_write_mb,
                network_sent_mb=net_sent_mb,
                network_recv_mb=net_recv_mb,
                files_scanned=0,
                detections_found=0,
                queue_size=0,
                active_workers=0
            )
            
        except Exception as e:
            self.performance_logger.error(f"Error collecting performance snapshot: {e}")
            return PerformanceSnapshot(
                timestamp=time.time(),
                cpu_percent=0, memory_mb=0, memory_percent=0,
                disk_io_read_mb=0, disk_io_write_mb=0,
                network_sent_mb=0, network_recv_mb=0,
                files_scanned=0, detections_found=0,
                queue_size=0, active_workers=0
            )

    def _update_performance_metrics(self, snapshot):
        """Update aggregate performance metrics."""
        self.performance_metrics['peak_cpu_percent'] = max(
            self.performance_metrics['peak_cpu_percent'], 
            snapshot.cpu_percent
        )
        self.performance_metrics['peak_memory_mb'] = max(
            self.performance_metrics['peak_memory_mb'], 
            snapshot.memory_mb
        )
        
        if len(self.performance_history) > 1:
            cpu_values = [s.cpu_percent for s in self.performance_history]
            memory_values = [s.memory_mb for s in self.performance_history]
            
            self.performance_metrics['avg_cpu_percent'] = sum(cpu_values) / len(cpu_values)
            self.performance_metrics['avg_memory_mb'] = sum(memory_values) / len(memory_values)

    def _log_performance_details(self, snapshot):
        """Log detailed performance snapshot."""
        self.performance_logger.info(
            f"Performance Snapshot | "
            f"CPU: {snapshot.cpu_percent:.1f}% | "
            f"Memory: {snapshot.memory_mb:.1f}MB ({snapshot.memory_percent:.1f}%) | "
            f"Disk I/O: R:{snapshot.disk_io_read_mb:.1f}MB W:{snapshot.disk_io_write_mb:.1f}MB | "
            f"Network: S:{snapshot.network_sent_mb:.1f}MB R:{snapshot.network_recv_mb:.1f}MB | "
            f"Queue: {snapshot.queue_size} | Workers: {snapshot.active_workers}"
        )

    def update_scanner_stats(self, files_scanned, detections_found, queue_size, active_workers):
        """Update scanner stats in latest performance snapshot."""
        with self.lock_performance:
            if self.performance_history:
                latest = self.performance_history[-1]
                latest.files_scanned = files_scanned
                latest.detections_found = detections_found
                latest.queue_size = queue_size
                latest.active_workers = active_workers

    def update_worker_stats(self, worker_id, processing_time, error_occurred=False):
        """Update individual worker statistics."""
        with self.lock_stats:
            if worker_id not in self.worker_stats:
                self.worker_stats[worker_id] = {
                    'files_processed': 0,
                    'processing_time': 0.0,
                    'errors': 0,
                    'last_activity': 0
                }
            stats = self.worker_stats[worker_id]
            stats['files_processed'] += 1
            stats['processing_time'] += processing_time
            stats['last_activity'] = time.time()
            if error_occurred:
                stats['errors'] += 1


    def calculate_time_estimates(self, total_files_processed, total_files_estimated, start_time):
        """Calculate scan completion time estimates."""
        current_time = time.time()
        elapsed_time = current_time - start_time
        
        if elapsed_time > 0 and total_files_processed > 0:
            current_rate = total_files_processed / elapsed_time
            
            with self.lock_stats:
                self.scan_estimates['current_rate'] = current_rate
                self.scan_estimates['total_files_estimate'] = total_files_estimated
                
                if total_files_estimated > total_files_processed:
                    remaining_files = total_files_estimated - total_files_processed
                    eta_seconds = remaining_files / current_rate if current_rate > 0 else None
                    self.scan_estimates['eta_seconds'] = eta_seconds
                    self.scan_estimates['completion_estimate'] = current_time + eta_seconds if eta_seconds else None
                
                if len(self.performance_history) > 1:
                    time_window = min(300, len(self.performance_history) * 5)
                    recent_snapshots = list(self.performance_history)[-int(time_window/5):]
                    if len(recent_snapshots) > 1:
                        time_diff = recent_snapshots[-1].timestamp - recent_snapshots[0].timestamp
                        files_diff = recent_snapshots[-1].files_scanned - recent_snapshots[0].files_scanned
                        self.scan_estimates['average_rate'] = files_diff / time_diff if time_diff > 0 else 0

    def log_comprehensive_stats(self):
        """Log comprehensive statistics summary."""
        with self.lock_stats, self.lock_performance:
            perf_summary = {
                'peak_cpu_percent': self.performance_metrics['peak_cpu_percent'],
                'avg_cpu_percent': self.performance_metrics['avg_cpu_percent'],
                'peak_memory_mb': self.performance_metrics['peak_memory_mb'],
                'avg_memory_mb': self.performance_metrics['avg_memory_mb'],
                'samples_collected': len(self.performance_history)
            }
            
            worker_summary = {}
            for worker_id, stats in self.worker_stats.items():
                avg_processing_time = stats['processing_time'] / stats['files_processed'] if stats['files_processed'] > 0 else 0
                error_rate = stats['errors'] / stats['files_processed'] * 100 if stats['files_processed'] > 0 else 0
                worker_summary[worker_id] = {
                    'files_processed': stats['files_processed'],
                    'avg_processing_time_ms': avg_processing_time * 1000,
                    'error_rate_percent': error_rate
                }
            
            self.stats_logger.info("=" * 60)
            self.stats_logger.info("COMPREHENSIVE STATISTICS SUMMARY")
            self.stats_logger.info("=" * 60)
            self.stats_logger.info(f"Performance Metrics: {json.dumps(perf_summary, indent=2)}")
            self.stats_logger.info(f"Time Estimates: {json.dumps(self.scan_estimates, indent=2, default=str)}")
            self.stats_logger.info(f"Worker Summary: {json.dumps(worker_summary, indent=2)}")
            self.stats_logger.info("=" * 60)

    def get_current_stats_for_upload(self):
        """Get current statistics for webhook upload."""
        with self.lock_stats, self.lock_performance:
            current_snapshot = self.performance_history[-1] if self.performance_history else None
            
            return {
                'hostname': self.hostname,
                'os_info': self.os_info,
                'ipAddress': self.ip_address,
                'timestamp': time.time(),
                'log_type': 'statistics',
                'performance_metrics': self.performance_metrics.copy(),
                'scan_estimates': self.scan_estimates.copy(),
                'current_performance': current_snapshot.to_dict() if current_snapshot else None,
                'worker_count': len(self.worker_stats),
                'total_worker_files': sum(stats['files_processed'] for stats in self.worker_stats.values())
            }

    def stop_monitoring(self):
        """Stop monitoring and log final stats."""
        if self._stopped:
            return
        self._stopped = True
        self.monitoring_active = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        self.log_comprehensive_stats()
        self.stats_logger.info("=== Statistics Manager Stopped ===")
        self.performance_logger.info("=== Performance Monitoring Ended ===")

    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.stop_monitoring()
        except Exception:
            pass


class LogManager:
    """Centralized log manager with standardized webhook uploads."""
    
    def __init__(self, config):
        self.config = config
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id

        self.log_files = {
            LogType.ALERT: os.path.join(self.config.logs_dir, f"alerts_{self.config.run_id}.log"),
            LogType.STATISTICS: os.path.join(self.config.logs_dir, f"statistics_{self.config.run_id}.log"),
            LogType.ERROR: os.path.join(self.config.logs_dir, f"scan_errors_{self.config.run_id}.log"),
            LogType.PERFORMANCE: os.path.join(self.config.logs_dir, f"performance_{self.config.run_id}.log"),
            LogType.UPLOAD: os.path.join(self.config.logs_dir, f"uploads_{self.config.run_id}.log"),
            LogType.SYSTEM: os.path.join(self.config.logs_dir, f"system_{self.config.run_id}.log"),
        }
        
        self.loggers = {}
        for log_type in LogType:
            self.loggers[log_type] = self._setup_logger(log_type)
        
        self.webhook_queue = Queue()
        self.webhook_thread = None
        self.webhook_active = True
        self.upload_stats = {
            'total_logs': 0,
            'successful_uploads': 0,
            'failed_uploads': 0,
            'by_type': {log_type.value: 0 for log_type in LogType}
        }
        self._stopped = False
        
        if UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and API_ENDPOINT:
            self._start_webhook_thread()
        
        self.log_system("Enhanced Log Manager initialized with standardized logging")

    def _setup_logger(self, log_type: LogType):
        """Setup individual logger for specific log type."""
        logger_name = f"{log_type.value}_logger_{id(self)}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
        
        try:
            handler = logging.FileHandler(
                self.log_files[log_type], 
                encoding="utf-8", 
                mode="w"
            )
            handler.setLevel(logging.INFO)
            
            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.propagate = False
            
            return logger
            
        except Exception as e:
            print(f"Failed to setup logger for {log_type.value}: {e}")
            return logging.getLogger()

    def _start_webhook_thread(self):
        """Start background webhook upload thread."""
        self.webhook_thread = threading.Thread(target=self._webhook_worker, daemon=True)
        self.webhook_thread.start()
        self.log_upload("Webhook upload thread started for standardized log entries")

    def _webhook_worker(self):
        """Background worker for uploading log entries.

        Drains the queue before exiting so telemetry logs are not dropped at
        shutdown. Exits only when the sentinel arrives, or when the queue is
        empty AND webhook_active was flipped to False by stop_logging().
        """
        while True:
            try:
                standard_log = self.webhook_queue.get(timeout=1.0)

                if standard_log is None:
                    break

                # Batch log events too - on a storm scan this queue carries the bulk of
                # the per-file/system chatter, and one POST per line was the same
                # round-trip-bound bottleneck the match channel hit.
                batch, saw_sentinel = _collect_batch(self.webhook_queue, standard_log)
                self._upload_standard_batch(batch)
                for _ in batch:
                    self.webhook_queue.task_done()
                if saw_sentinel:
                    break

            except Empty:
                if not self.webhook_active:
                    break
                continue
            except Exception as e:
                err_type = type(e).__name__
                err_msg = f"Webhook worker error: {err_type}"
                if str(e):
                    err_msg += f": {str(e)}"
                self.log_error(err_msg)
                continue

    def _upload_standard_batch(self, items):
        """Upload a batch of log entries as NDJSON. Per-event accounting on failure."""
        if not items:
            return
        n = len(items)
        try:
            response = _post_ndjson(_get_webhook_endpoint(API_ENDPOINT), API_KEY, items, timeout=10)
            if 200 <= response.status_code < 300:
                self.upload_stats['successful_uploads'] += n
            else:
                self.upload_stats['failed_uploads'] += n
                self.loggers[LogType.UPLOAD].error(
                    f"Webhook batch upload failed (HTTP {response.status_code}, {n} event(s)): "
                    f"{response.text[:200]}"
                )
        except Exception as e:
            self.upload_stats['failed_uploads'] += n
            self.loggers[LogType.UPLOAD].error(f"Webhook batch upload error ({n} event(s)): {e}")

    def _log_with_webhook(self, log_type, message, level="INFO", data=None):
        """Log message to file and optionally upload to webhook."""
        logger = self.loggers[log_type]
        if level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        elif level == "DEBUG":
            logger.debug(message)
        else:
            logger.info(message)
        
        self.upload_stats['total_logs'] += 1
        self.upload_stats['by_type'][log_type.value] += 1
        
        if (UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and API_ENDPOINT and self.webhook_thread and
            self.webhook_thread.is_alive() and log_type != LogType.UPLOAD):
            try:
                standard_log = create_standard_log(
                    log_type=log_type.value,
                    hostname=self.hostname,
                    os_info=self.os_info,
                    ip_address=self.ip_address,
                    scan_id=self.scan_id,
                    message=message,
                    level=level,
                    data=data
                )
                self.webhook_queue.put(standard_log, timeout=1.0)
            except Exception:
                pass

    def log_alert(self, message: str, data=None):
        """Log alert message."""
        self._log_with_webhook(LogType.ALERT, message, "INFO", data)

    def log_statistics(self, message: str, data=None):
        """Log statistics message."""
        self._log_with_webhook(LogType.STATISTICS, message, "INFO", data)

    def _log_critical(self, log_type: LogType, message: str, data=None):
        """Log a message, attempting an immediate synchronous webhook send first so
        it is not stuck behind whatever backlog already exists in the normal async
        queue - falls back to that same queue only if the direct send fails.

        For dashboard-critical, once-per-scan signals (scan started, target
        completed) where the scan can otherwise still be running - and the
        delivery queue backlogged with the telemetry it has produced so far - by
        the time this fires.
        """
        self.loggers[log_type].info(message)
        self.upload_stats['total_logs'] += 1
        self.upload_stats['by_type'][log_type.value] += 1

        if not (UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and API_ENDPOINT):
            return

        standard_log = create_standard_log(
            log_type=log_type.value, hostname=self.hostname, os_info=self.os_info,
            ip_address=self.ip_address, scan_id=self.scan_id, message=message, level="INFO",
            data=data
        )
        try:
            response = requests.post(
                url=_get_webhook_endpoint(API_ENDPOINT),
                headers={"Authorization": API_KEY, "Content-Type": "application/json"},
                json=standard_log.to_dict(),
                timeout=DEFAULT_TIMEOUT_SECS
            )
            if 200 <= response.status_code < 300:
                self.upload_stats['successful_uploads'] += 1
                return
            self.loggers[LogType.UPLOAD].warning(
                f"Critical log immediate send failed (HTTP {response.status_code}): "
                f"{response.text} - falling back to async queue"
            )
        except Exception as e:
            # Ambiguous outcome: the request may have reached the collector even though
            # we never saw a clean response (e.g. a read timeout after the server already
            # wrote the row). Requeuing risks a duplicate row for this once-per-scan event -
            # logged here so that's visible rather than silent, consistent with this
            # scanner's existing "honest books over exact-once" delivery philosophy.
            self.loggers[LogType.UPLOAD].warning(
                f"Critical log immediate send raised {type(e).__name__}: {e} - falling back "
                f"to async queue (may deliver a duplicate if the request actually landed)"
            )

        if self.webhook_thread and self.webhook_thread.is_alive():
            try:
                self.webhook_queue.put(standard_log, timeout=1.0)
            except Exception:
                self.upload_stats['failed_uploads'] += 1
                self.loggers[LogType.UPLOAD].error(
                    f"Critical log dropped for {standard_log.type}: async queue unavailable"
                )
        else:
            self.upload_stats['failed_uploads'] += 1
            self.loggers[LogType.UPLOAD].error(
                f"Critical log dropped for {standard_log.type}: no async queue to fall back to"
            )

    def log_statistics_critical(self, message: str, data=None):
        """log_statistics, but see _log_critical."""
        self._log_critical(LogType.STATISTICS, message, data)

    def log_performance_critical(self, message: str, data=None):
        """log_performance, but see _log_critical."""
        self._log_critical(LogType.PERFORMANCE, message, data)

    def log_error(self, message: str, data=None):
        """Log error message."""
        self._log_with_webhook(LogType.ERROR, message, "ERROR", data)

    def log_performance(self, message: str, data=None):
        """Log performance message."""
        self._log_with_webhook(LogType.PERFORMANCE, message, "INFO", data)

    def log_upload(self, message: str, data=None):
        """Log upload message."""
        self._log_with_webhook(LogType.UPLOAD, message, "INFO", data)

    def log_system(self, message: str, data=None):
        """Log system message."""
        self._log_with_webhook(LogType.SYSTEM, message, "INFO", data)

    def log_scan_progress(self, files_scanned: int, files_skipped: int, detections: int,
                         queue_size: int, scan_rate: float, additional_metrics=None):
        """Log comprehensive scan progress."""
        additional_metrics = additional_metrics or {}
        progress_data = {
            'files_scanned': files_scanned,
            'files_skipped': files_skipped,
            'total_detections': detections,
            'queue_size': queue_size,
            'scan_rate_files_per_sec': scan_rate,
            # Flattened for the "Capacity vs Backpressure" dashboard widget, which filters on a
            # top-level active_workers column - previously only reachable at metrics.active_workers.
            'active_workers': additional_metrics.get('active_workers'),
            'metrics': additional_metrics
        }
        
        message = (
            f"Scan Progress | Files: {files_scanned} scanned, {files_skipped} skipped | "
            f"Detections: {detections} | Queue: {queue_size} | Rate: {scan_rate:.1f} files/sec"
        )
        
        self.log_statistics(message, progress_data)

    def log_worker_performance(self, worker_id: str, files_processed: int, 
                              avg_time_ms: float, error_rate: float):
        """Log individual worker performance."""
        worker_data = {
            'worker_id': worker_id,
            'files_processed': files_processed,
            'avg_processing_time_ms': avg_time_ms,
            'error_rate_percent': error_rate
        }
        
        message = (
            f"Worker Performance | {worker_id} | "
            f"Files: {files_processed} | Avg Time: {avg_time_ms:.1f}ms | "
            f"Error Rate: {error_rate:.1f}%"
        )
        
        self.log_performance(message, worker_data)

    def log_system_resources(self, cpu_percent: float, memory_mb: float, 
                            disk_io_mb: float, network_mb: float):
        """Log system resource utilization."""
        resource_data = {
            'cpu_percent': cpu_percent,
            'memory_mb': memory_mb,
            'disk_io_mb': disk_io_mb,
            'network_mb': network_mb
        }
        
        message = (
            f"System Resources | CPU: {cpu_percent:.1f}% | "
            f"Memory: {memory_mb:.1f}MB | Disk I/O: {disk_io_mb:.1f}MB | "
            f"Network: {network_mb:.1f}MB"
        )
        
        self.log_performance(message, resource_data)


    def log_time_estimates(self, eta_seconds, completion_time,
                          current_rate: float, files_remaining: int):
        """Log time estimation data."""
        estimate_data = {
            'eta_seconds': eta_seconds,
            'estimated_completion': completion_time,
            'current_rate_files_per_sec': current_rate,
            'files_remaining': files_remaining
        }
        
        eta_str = f"{datetime.timedelta(seconds=int(eta_seconds))}" if eta_seconds else "Unknown"
        message = (
            f"Time Estimates | ETA: {eta_str} | "
            f"Rate: {current_rate:.1f} files/sec | "
            f"Remaining: {files_remaining} files"
        )
        
        self.log_statistics(message, estimate_data)

    def get_upload_statistics(self):
        """Get current webhook upload statistics."""
        return self.upload_stats.copy()

    def log_final_summary(self):
        """Log comprehensive final summary."""
        summary_data = {
            'total_logs_generated': self.upload_stats['total_logs'],
            'webhook_successful_uploads': self.upload_stats['successful_uploads'],
            'webhook_failed_uploads': self.upload_stats['failed_uploads'],
            'logs_by_type': self.upload_stats['by_type'].copy(),
            'log_files_created': {log_type.value: self.log_files[log_type] for log_type in LogType}
        }
        
        success_rate = 0
        if self.upload_stats['total_logs'] > 0:
            success_rate = (self.upload_stats['successful_uploads'] / self.upload_stats['total_logs']) * 100
        
        message = (
            f"Logging Summary | Total Logs: {self.upload_stats['total_logs']} | "
            f"Webhook Uploads: {self.upload_stats['successful_uploads']} successful, "
            f"{self.upload_stats['failed_uploads']} failed | "
            f"Success Rate: {success_rate:.1f}%"
        )
        
        self.log_system(message, summary_data)

    def write_scan_summary(self, summary: dict):
        """Write a single machine-readable scan summary JSON for this run.

        The six per-category text logs are for humans; this one file is for tools - an
        Action Center follow-up, the test skill, or the customer's own automation reads one
        JSON instead of grepping six logs. Written atomically (tmp + os.replace) so a
        reader never sees a half-written file, and the temp is cleaned up on failure.

        This matters most in the case this edition is least protected against: the console's
        Cancel button hard-kills the payload mid-scan, so nothing is flushed to the collector
        and this local file is the only surviving evidence of what the run had done.
        Ported from the XDR edition; XDR-specific fields (lookup datasets, CPU governor,
        posture) are dropped and the webhook delivery books take their place.
        """
        path = os.path.join(self.config.logs_dir, f"scan_summary_{self.config.run_id}.json")
        record = {
            "schema": "yara_scan_summary/v1",
            "edition": "xsiam",
            "run_id": self.config.run_id,
            "scan_id": self.scan_id,
            "rule_hash": getattr(self.config, "rule_hash", ""),
            "hostname": self.hostname,
            "os_info": self.os_info,
            "ip_address": self.ip_address,
            "scanner_version": __version__,
        }
        record.update(summary or {})
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(record, f, default=str, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
            self.log_system(f"Scan summary written: {os.path.basename(path)}")
        except Exception as e:
            # Don't leave a half-written temp behind (e.g. disk full mid-dump).
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            self.log_error(f"Failed to write scan summary JSON: {e}")
        return path

    def stop_logging(self):
        """Stop all logging activities."""
        if self._stopped:
            return
        self._stopped = True
        if self.webhook_thread and self.webhook_thread.is_alive():
            start_wait = time.time()
            initial_queue_size = self.webhook_queue.qsize()
            max_wait_time = _compute_drain_budget(initial_queue_size)
            if initial_queue_size > 0:
                self.log_upload(
                    f"Waiting for {initial_queue_size} pending standardized log uploads (max {max_wait_time:.0f}s)..."
                )
            while self.webhook_queue.qsize() > 0 and (time.time() - start_wait) < max_wait_time:
                time.sleep(0.2)
            self.webhook_active = False
            try:
                self.webhook_queue.put(None, timeout=0.2)
            except Exception:
                pass
            self.webhook_thread.join(timeout=THREAD_CLEANUP_TIMEOUT)
        
        self.log_final_summary()
        
        for log_type, logger in self.loggers.items():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)

    def __del__(self):
        """Cleanup on destruction."""
        try:
            self.stop_logging()
        except Exception:
            pass


class SystemResourceMonitor:
    """Dedicated system resource monitoring with standardized uploads."""
    
    def __init__(self, config, log_manager, webhook_uploader):
        self.config = config
        self.log_manager = log_manager
        self.webhook_uploader = webhook_uploader
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id

        self.monitoring_interval = 10
        self.upload_interval = 45
        self.alert_thresholds = {
            'cpu_percent': 90,
            'memory_percent': 85,
            'disk_usage_percent': 95
        }
        
        self.resource_history = deque(maxlen=360)
        self.alert_history = deque(maxlen=100)
        self.monitoring_active = True
        self.monitoring_thread = None
        self.last_upload_time = 0
        
        try:
            self.process = psutil.Process()
            self.system_boot_time = psutil.boot_time()
            if platform.system() != "Darwin":
                try:
                    self.initial_io = self.process.io_counters()
                except:
                    self.initial_io = None
            else:
                self.initial_io = None
            self.initial_net = psutil.net_io_counters()
            self.initial_cpu_times = self.process.cpu_times()
            
        except ImportError:
            self.log_manager.log_error("psutil not available - resource monitoring limited")
            self.process = None
        except Exception as e:
            self.log_manager.log_error(f"Failed to initialize resource monitoring: {e}")
            self.process = None
        
        self.start_monitoring()

    def start_monitoring(self):
        """Start background resource monitoring."""
        if not getattr(self.config, "enable_resource_monitoring", True):
            self.log_manager.log_system("System resource monitoring disabled in light profile")
            return
        if not self.process:
            return
            
        self.monitoring_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitoring_thread.start()
        self.log_manager.log_system("System resource monitoring started")

    def _monitoring_worker(self):
        """Background worker for continuous resource monitoring."""
        self.log_manager.log_performance("System resource monitoring worker started")
        
        while self.monitoring_active:
            try:
                resource_data = self._collect_resource_snapshot()
                
                if resource_data:
                    self.resource_history.append(resource_data)
                    self._check_resource_alerts(resource_data)
                    
                    current_time = time.time()
                    if current_time - self.last_upload_time >= self.upload_interval:
                        self._upload_resource_data(resource_data)
                        self.last_upload_time = current_time
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                self.log_manager.log_error(f"Resource monitoring error: {e}")
                time.sleep(self.monitoring_interval * 2)

    def _collect_resource_snapshot(self):
        """Collect comprehensive system resource snapshot."""
        if not self.process:
            return None
            
        try:
            current_time = time.time()
            
            cpu_percent = self.process.cpu_percent()
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            memory_percent = self.process.memory_percent()

            if self.initial_io is not None and platform.system() != "Darwin":
                try:
                    current_io = self.process.io_counters()
                    io_read_mb = (current_io.read_bytes - self.initial_io.read_bytes) / 1024 / 1024
                    io_write_mb = (current_io.write_bytes - self.initial_io.write_bytes) / 1024 / 1024
                except (AttributeError, NotImplementedError):
                    io_read_mb = 0
                    io_write_mb = 0
            else:
                io_read_mb = 0
                io_write_mb = 0

            system_cpu = psutil.cpu_percent(interval=None)
            system_memory = psutil.virtual_memory()
            system_disk = psutil.disk_usage('/')

            current_net = psutil.net_io_counters()
            net_sent_mb = (current_net.bytes_sent - self.initial_net.bytes_sent) / 1024 / 1024
            net_recv_mb = (current_net.bytes_recv - self.initial_net.bytes_recv) / 1024 / 1024
            
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            
            return {
                'process': {
                    'cpu_percent': cpu_percent,
                    'memory_mb': memory_mb,
                    'memory_percent': memory_percent,
                    'io_read_mb': io_read_mb,
                    'io_write_mb': io_write_mb,
                    'thread_count': self.process.num_threads(),
                    'file_descriptors': self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
                },
                'system': {
                    'cpu_percent': system_cpu,
                    'memory_total_mb': system_memory.total / 1024 / 1024,
                    'memory_available_mb': system_memory.available / 1024 / 1024,
                    'memory_used_percent': system_memory.percent,
                    'disk_total_gb': system_disk.total / 1024 / 1024 / 1024,
                    'disk_free_gb': system_disk.free / 1024 / 1024 / 1024,
                    'disk_used_percent': system_disk.percent,
                    'load_avg_1m': load_avg[0],
                    'load_avg_5m': load_avg[1],
                    'load_avg_15m': load_avg[2]
                },
                'network': {
                    'sent_mb': net_sent_mb,
                    'recv_mb': net_recv_mb,
                    'total_mb': net_sent_mb + net_recv_mb
                },
                'efficiency': {
                    'memory_efficiency': max(0, 100 - memory_percent),
                    'cpu_efficiency': max(0, 100 - cpu_percent),
                    'io_intensity': (io_read_mb + io_write_mb) / max(memory_mb, 1),
                    'network_intensity': (net_sent_mb + net_recv_mb) / max(memory_mb, 1)
                }
            }
            
        except Exception as e:
            self.log_manager.log_error(f"Error collecting resource snapshot: {e}")
            return None

    def _check_resource_alerts(self, resource_data):
        """Check for resource usage alerts."""
        alerts = []
        
        if resource_data['process']['cpu_percent'] > self.alert_thresholds['cpu_percent']:
            alerts.append({
                'type': 'high_cpu',
                'value': resource_data['process']['cpu_percent'],
                'threshold': self.alert_thresholds['cpu_percent']
            })
        
        if resource_data['process']['memory_percent'] > self.alert_thresholds['memory_percent']:
            alerts.append({
                'type': 'high_memory',
                'value': resource_data['process']['memory_percent'],
                'threshold': self.alert_thresholds['memory_percent']
            })
        
        if resource_data['system']['disk_used_percent'] > self.alert_thresholds['disk_usage_percent']:
            alerts.append({
                'type': 'high_disk_usage',
                'value': resource_data['system']['disk_used_percent'],
                'threshold': self.alert_thresholds['disk_usage_percent']
            })
        
        for alert in alerts:
            alert_message = (
                f"RESOURCE ALERT: {alert['type']} - "
                f"{alert['value']:.1f}% exceeds threshold of {alert['threshold']}%"
            )
            
            self.log_manager.log_error(alert_message, {
                'alert_type': alert['type'],
                'current_value': alert['value'],
                'threshold': alert['threshold']
            })
            
            self.alert_history.append({
                'timestamp': time.time(),
                'alert_type': alert['type'],
                'value': alert['value'],
                'threshold': alert['threshold']
            })

    def _upload_resource_data(self, resource_data):
        """Upload resource data with standardized format."""
        try:
            trends = self._calculate_resource_trends()
            
            enhanced_data = resource_data.copy()
            enhanced_data.update({
                'trends': trends,
                'alert_count_last_hour': len([a for a in self.alert_history
                                            if time.time() - a['timestamp'] < 3600]),
                'monitoring_duration_minutes': (time.time() - self.system_boot_time) / 60,
                # Flattened for the dashboard's CPU/memory widgets, which filter on these exact
                # top-level column names - previously only reachable nested under process/system,
                # so sys_cpu_percent != null (etc.) never matched and the widgets stayed empty.
                'proc_cpu_percent': resource_data['process']['cpu_percent'],
                'proc_memory_mb': resource_data['process']['memory_mb'],
                'sys_cpu_percent': resource_data['system']['cpu_percent'],
                'sys_memory_used_percent': resource_data['system']['memory_used_percent'],
            })
            
            standard_log = create_standard_log(
                log_type='system_resource_snapshot',
                hostname=self.hostname,
                os_info=self.os_info,
                ip_address=self.ip_address,
                scan_id=self.scan_id,
                message=f"System resources - CPU: {resource_data['process']['cpu_percent']:.1f}%, Memory: {resource_data['process']['memory_mb']:.1f}MB",
                level="INFO",
                data=enhanced_data
            )
            
            self.webhook_uploader._queue_standard_upload(standard_log)
            
        except Exception as e:
            self.log_manager.log_error(f"Failed to upload resource data: {e}")

    def _calculate_resource_trends(self):
        """Calculate resource usage trends."""
        if len(self.resource_history) < 2:
            return {}
        
        try:
            recent_cutoff = time.time() - 600
            recent_data = [r for r in self.resource_history if 'process' in r]
            
            if len(recent_data) < 2:
                return {}
            
            cpu_values = [r['process']['cpu_percent'] for r in recent_data]
            memory_values = [r['process']['memory_mb'] for r in recent_data]
            
            trends = {
                'cpu_trend': 'stable',
                'memory_trend': 'stable',
                'cpu_avg_10min': sum(cpu_values) / len(cpu_values),
                'memory_avg_10min': sum(memory_values) / len(memory_values),
                'data_points': len(recent_data)
            }
            
            if len(cpu_values) >= 5:
                cpu_slope = (cpu_values[-1] - cpu_values[0]) / len(cpu_values)
                if cpu_slope > 2:
                    trends['cpu_trend'] = 'increasing'
                elif cpu_slope < -2:
                    trends['cpu_trend'] = 'decreasing'
                    
                memory_slope = (memory_values[-1] - memory_values[0]) / len(memory_values)
                if memory_slope > 5:
                    trends['memory_trend'] = 'increasing'
                elif memory_slope < -5:
                    trends['memory_trend'] = 'decreasing'
            
            return trends
            
        except Exception as e:
            self.log_manager.log_error(f"Error calculating resource trends: {e}")
            return {}

    def get_resource_summary(self):
        """Get comprehensive resource usage summary."""
        if not self.resource_history:
            return {}
        
        try:
            cpu_values = [r['process']['cpu_percent'] for r in self.resource_history if 'process' in r]
            memory_values = [r['process']['memory_mb'] for r in self.resource_history if 'process' in r]
            
            return {
                'monitoring_duration_seconds': len(self.resource_history) * self.monitoring_interval,
                'data_points_collected': len(self.resource_history),
                'cpu_stats': {
                    'min': min(cpu_values) if cpu_values else 0,
                    'max': max(cpu_values) if cpu_values else 0,
                    'avg': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                    'current': cpu_values[-1] if cpu_values else 0
                },
                'memory_stats': {
                    'min_mb': min(memory_values) if memory_values else 0,
                    'max_mb': max(memory_values) if memory_values else 0,
                    'avg_mb': sum(memory_values) / len(memory_values) if memory_values else 0,
                    'current_mb': memory_values[-1] if memory_values else 0
                },
                'alerts_triggered': len(self.alert_history),
                'last_alert_time': max([a['timestamp'] for a in self.alert_history]) if self.alert_history else None
            }
            
        except Exception as e:
            self.log_manager.log_error(f"Error calculating resource summary: {e}")
            return {}

    def stop_monitoring(self):
        """Stop resource monitoring."""
        self.monitoring_active = False
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        final_summary = self.get_resource_summary()
        if final_summary:
            standard_log = create_standard_log(
                log_type='resource_monitoring_summary',
                hostname=self.hostname,
                os_info=self.os_info,
                ip_address=self.ip_address,
                scan_id=self.scan_id,
                message=f"Resource monitoring completed: {final_summary['data_points_collected']} snapshots, {final_summary['alerts_triggered']} alerts",
                level="INFO",
                data=final_summary
            )
            self.webhook_uploader._queue_standard_upload(standard_log, priority=True)


# ============================================================================
# CONFIGURATION
# ============================================================================

class ScanConfig:
    """Configuration class for scan settings and environment setup."""

    def __init__(self, yarafile, scan_folder=None, alert_severity="low"):
        self.hostname, self.ip_addresses, self.os_info = get_system_info()
        self.run_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        self.light_profile = True
        parsed_alert_severity = _parse_alert_severity(alert_severity, "alert_severity")
        self.alert_severity = "low" if parsed_alert_severity is None else parsed_alert_severity
        scanner_dir_override = os.environ.get("YARA_SCANNER_DIR")
        if scanner_dir_override and scanner_dir_override.strip():
            self.scanner_dir = scanner_dir_override.strip()
        elif platform.system() == "Windows":
            self.scanner_dir = "C:\\yara_scanner"
        elif platform.system() == "Darwin":
            self.scanner_dir = "/usr/local/yara_scanner"
        else:
            self.scanner_dir = "/opt/yara_scanner"

        self.logs_dir = os.path.join(self.scanner_dir, "logs")
        # Cooperative-cancellation control files (cancel.flag / running.json) live here.
        self.control_dir = os.path.join(self.scanner_dir, "control")
        os.makedirs(self.scanner_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        try:
            os.makedirs(self.control_dir, exist_ok=True)
        except Exception:
            pass

        is_windows = platform.system() == "Windows"
        self.alert_dir = os.path.join(self.scanner_dir, "alert")
        self.evidence_dir = os.path.join(self.scanner_dir, "evidence")
        self.failed_rules_dir = os.path.join(self.scanner_dir, "failed_rules")

        for directory in [self.alert_dir, self.evidence_dir, self.failed_rules_dir]:
            os.makedirs(directory, exist_ok=True)

        self.error_logger = ErrorLogger(self)
        self.exception_logger = ExceptionLogger(self)
        self.yarafile = yarafile
        self.scan_folder = scan_folder

        global API_KEY, API_ENDPOINT
        API_KEY = DEFAULT_API_KEY
        API_ENDPOINT = DEFAULT_API_ENDPOINT
        self.webhook_key_source = "default"
        self.webhook_endpoint_source = "default"

        self.error_logger.error_logger.info("Webhook API Key: Using hardcoded default")
        self.error_logger.error_logger.info(f"API Endpoint: {API_ENDPOINT}")
        self.error_logger.error_logger.info(f"Default alert severity: {self.alert_severity}")
        self.error_logger.error_logger.info(
            "Light profile active: reduced workers, reduced monitoring, and lower-impact scan execution"
        )

        
        try:
            if yarafile:
                self.error_logger.error_logger.info("Using YARA rules from provided parameter")
                self.yara_rule = decode_yara_rules(yarafile, self.error_logger)
            else:
                self.error_logger.error_logger.info("Using YARA rules from default configuration")
                if not YARA_RULE.strip():
                    raise ValueError("Default YARA_RULE is empty - must provide yarafile parameter")
                self.yara_rule = decode_yara_rules(YARA_RULE, self.error_logger)
        except Exception as e:
            self.error_logger.error_logger.error(f"CRITICAL: Failed to decode YARA rules: {e}")
            raise

        yara_hash = hashlib.sha256(self.yara_rule.encode('utf-8')).hexdigest()
        # scan_id must be unique per scan RUN, not per ruleset. Derived from the rule hash
        # alone (the previous "yara_<hash>" form), every host in a fleet running the same
        # rules - and every re-run on one host - reported under one identical scan_id, so
        # any consumer grouping by scan_id silently merged the whole fleet into a single
        # scan. Ported from the XDR edition. The hash prefix is kept (12 chars) so the
        # ruleset is still identifiable from the scan_id alone.
        self.rule_hash = yara_hash
        self.scan_id = f"{self.hostname}_{self.run_id}_yara_{yara_hash[:12]}"
        self.error_logger.error_logger.info(f"Scan ID: {self.scan_id} (rule hash: {yara_hash[:12]}...)")

        self.cleanup_script = os.path.join(
            self.scanner_dir, "cleanup_script.bat" if is_windows else "cleanup_script.sh"
        )
        self.file_mapping = os.path.join(self.evidence_dir, "file_mapping.txt")
        self.output_log = os.path.join(self.logs_dir, f"scanner_{self.run_id}.log")

        # minimum=0 because 0 legitimately means "no size cap"; a NEGATIVE value parsed
        # fine and made max_file_bytes negative, so every file failed the size check and
        # the scan reported success having scanned nothing.
        self.max_file_mb = _env_number("YARA_MAX_MB", 64, cast=int, minimum=0)
        self.max_file_bytes = self.max_file_mb * 1024 * 1024 if self.max_file_mb else 0

        cpu_count = os.cpu_count() or 2
        default_workers = 1 if cpu_count <= 2 else 2
        configured_workers = _env_number("YARA_THREADS", default_workers, cast=int, minimum=1)
        self.max_workers = max(1, min(2, configured_workers))
        self.scan_queue_size = max(
            2, _env_number("YARA_QUEUE_SIZE", self.max_workers * 2, cast=int, minimum=2)
        )
        # Default 30s, not 120s: this is the progress-heartbeat's sampling interval, and at
        # 120s a scan whose active phase is shorter than that emits NO progress telemetry at
        # all (the "Capacity vs Backpressure"/"Scan Rate" widgets stay empty). Measured on a
        # 15,589-file Windows scan: the active phase is well under 120s, so 120 produced zero
        # samples where 30 produces a usable series. Long fleet scans are unaffected - they
        # simply get proportionally more samples.
        #
        # Clamped to >=1s (same shape as scan_queue_size's max(2, ...) above): "0" is a
        # plausible thing for an operator to set trying to disable progress logging, and
        # threading.Event.wait(0) (or any negative) returns immediately, which would turn the
        # heartbeat into a busy-spin that re-takes lock_counts continuously and floods the
        # unbounded webhook queue. To actually disable progress logging, set a large interval.
        self.log_interval = max(1, _env_number("YARA_PROGRESS_LOG_SECS", 30, cast=int, minimum=1))
        self.enable_performance_monitoring = ENABLE_PERF_MONITOR
        self.enable_resource_monitoring = ENABLE_RESOURCE_MONITOR
        self.enable_fd_monitoring = ENABLE_FD_MONITOR
        self.track_real_paths = False
        self.light_throttle_enabled = True
        # All four throttle knobs take minimum=0: a negative sleep makes Event.wait()
        # return immediately, turning the throttle into the hot loop it exists to prevent.
        self.throttle_check_interval_secs = _env_number(
            "YARA_LIGHT_THROTTLE_CHECK_SECS", 0.5, minimum=0)
        self.high_cpu_threshold = _env_number("YARA_LIGHT_HIGH_CPU", 80, minimum=0)
        self.critical_cpu_threshold = _env_number("YARA_LIGHT_CRITICAL_CPU", 90, minimum=0)
        self.throttle_sleep_secs = _env_number("YARA_LIGHT_SLEEP_SECS", 0.02, minimum=0)
        self.critical_throttle_sleep_secs = _env_number(
            "YARA_LIGHT_CRITICAL_SLEEP_SECS", 0.08, minimum=0)
        self.queue_backoff_secs = _env_number("YARA_QUEUE_BACKOFF_SECS", 0.25, minimum=0)
        self.skip_extensions = {
            ".iso", ".img", ".dmg", ".vmdk", ".vhd", ".vhdx", ".qcow", ".qcow2", ".sparsebundle"
        }
        self.skip_filenames = {".ds_store", "thumbs.db", "desktop.ini"}
        self.skip_path_fragments = (
            "/node_modules/",
            "/__pycache__/",
            "/.git/",
            "/.svn/",
            "/.hg/",
            "/.venv/",
            "/venv/",
            "/.pytest_cache/",
            "/.mypy_cache/",
            "/.gradle/",
            "/.yarn/cache/",
            "/.npm/",
            "/library/caches/",
            "/appdata/local/temp/",
            "/appdata/local/packages/",
        )
        # The four browser cache/profile fragments that used to live above
        # ("/appdata/local/google/chrome/user data/default/cache/",
        #  "/appdata/local/microsoft/edge/user data/default/cache/",
        #  "/mozilla/firefox/profiles/", "/cache2/") were REMOVED, not moved:
        # browser caches and profile directories are common malware staging and
        # persistence areas, and skipping them was a detection blind spot on every
        # platform. Ported from the XDR edition.

        # Always-scan carve-outs (checked BEFORE skip logic): on macOS the broad
        # "/library/caches/" fragment above (and the mac skip dirs) would still bypass
        # browser caches, so re-open them surgically here. Safari is best-effort under
        # TCC / Full Disk Access.
        self.force_scan_fragments = (
            "/library/caches/google/chrome/",
            "/library/caches/chromium/",
            "/library/caches/microsoft edge/",
            "/library/caches/firefox/",
            "/library/caches/com.apple.safari/",
        )
        # Boundary skips the force-scan allowlist must never override. These keep the
        # scanner on THIS host rather than reducing noise, so a browser cache found under
        # one (e.g. a Time Machine disk at /Volumes/..., which holds one cache tree per
        # backup snapshot) must still be skipped - otherwise the carve-out silently turns
        # into an unbounded walk over mounted/removable/network media.
        self.force_scan_never_under = (
            "/volumes/",   # macOS mounted volumes (also in mac_skip_directory)
            "/media/",     # Linux removable media
            "/mnt/",       # Linux mounts
            "/net/",       # autofs network mounts
        )

        self.evidence_zip = os.path.join(
            self.evidence_dir, f"evidence_{self.hostname}_{self.run_id}.zip"
        )

        if is_windows:
            self.win_skip_drive = []
            self.win_skip_folder = [
                "C:\\ProgramData\\Cyvera",
                "C:\\ProgramData\\Microsoft Defender",
                "C:\\Program Files\\Palo Alto Networks",
                "C:\\Program Files (x86)\\Palo Alto Networks",
                "C:\\Program Files\\Cyvera",
                "C:\\Program Files (x86)\\Cyvera",
                "C:\\yara_scanner\\",
                "C:\\$Recycle.Bin",
                "C:\\System Volume Information",
                self.scanner_dir,
            ]
            # Cyvera (the Cortex/Traps agent) is covered above via its known install roots,
            # not via a fragment match. An earlier version of this fix tried
            # win_skip_fragments = ("/cyvera/",), an unanchored "anywhere in the path" check
            # meant to replace the broken win_skip_patterns glob below - but that made ANY
            # directory literally named "cyvera" a permanent scan blind spot, including
            # world-writable locations no legitimate install ever uses: adversarial review
            # demonstrated C:\Users\cyvera, C:\Users\Public\cyvera, C:\Temp\cyvera and even
            # D:\cyvera (any drive, since the fragment carried no drive anchor) were all
            # wrongly skipped. Anyone able to create such a directory - not just the vendor -
            # would get a free evasion vector. Enumerating the real install roots instead
            # keeps coverage bounded to admin-writable locations, matching the security model
            # every other win_skip_folder entry already relies on.
            #
            # The matcher this replaced, win_skip_patterns, was a custom "C:\*\cyvera\*" glob
            # confirmed by direct execution to never match ANY path: it split the drive
            # letter off the pattern via string ops but compared against a path that had
            # already had ITS drive letter stripped by os.path.splitdrive, so the literal
            # "c:" component could never be found; separately, "*" was compared as a literal
            # string, not a wildcard.
            # Normalise to bare directory paths with NO trailing separator, on every
            # platform. os.path.normpath only strips a trailing "\" when running on Windows
            # itself, so the same list had two different shapes depending on host OS and the
            # boundary check below would have had to handle both. The len<=3 guard keeps a
            # drive root ("c:\") from being reduced to a bare drive letter ("c:"), which
            # would then prefix-match the entire drive.
            self.win_skip_folder = [
                p if len(p) <= 3 else p.rstrip("\\")
                for p in (os.path.normpath(path.lower()) for path in self.win_skip_folder)
            ]
            self.skip_paths = set(self.win_skip_folder)

        elif platform.system() == "Linux":
            self.lin_skip_directory = [
                "/sys/", "/proc/", "/dev/", "/run/", "/tmp/.X11-unix/",
                "/var/run/", "/lost+found/", "/media/", "/opt/yara_scanner/",
                os.path.normpath(self.scanner_dir).rstrip("/") + "/",
            ]
            self.skip_paths = set(self.lin_skip_directory)
        
        elif platform.system() == "Darwin":
            self.mac_skip_directory = [
                '/System/', '/private/var/folders/', '/private/var/db/',
                '/private/var/root/', '/private/var/vm/', '/private/var/log/',
                '/private/tmp/', '/dev/', '/Volumes/', '/.Spotlight-V100/',
                '/.DocumentRevisions-V100/', '/.fseventsd/', '/.TemporaryItems/',
                '/.Trashes/', '/Library/Application Support/PaloAltoNetworks/Traps/',
                '/Library/Developer/', '/Library/Caches/', '/Library/Logs/',
                'Library/Containers/', 'Library/Caches/',
                'Library/Application Support/Google/',
                'Library/Application Support/JetBrains/',
                'Library/Application Support/Code/', 'Library/Application Support/Slack/',
                'Library/Developer/', 'Library/Android/', 'Library/Python/',
                'Library/Logs/', 'Library/Metadata/', 'Library/Group Containers/',
                'PycharmProjects/', 'WebstormProjects/', 'node_modules/',
                '.venv/', 'venv/', '__pycache__/', '.pytest_cache/', '.mypy_cache/',
                '.gradle/', '.android/', '.dart_tool/', 'build/', 'dist/',
                '.git/', '.svn/', '.idea/', '.vscode/',
                '.app/Contents/Frameworks/', '.app/Contents/Resources/',
                '.app/Contents/_CodeSignature/',
                '/Applications/Xcode.app/Contents/',
                '/Applications/Android Studio.app/Contents/',
                '/Applications/Docker.app/Contents/',
                '/Applications/VMware Fusion.app/Contents/',
                '/Applications/PyCharm CE.app/Contents/',
                '/Applications/WebStorm.app/Contents/',
                '/Applications/iMovie.app/Contents/',
                os.path.normpath(self.scanner_dir).rstrip("/") + "/",
            ]
            # Case-fold at construction, matching win_skip_folder's own .lower() - APFS is
            # case-insensitive by default, and the matching code compares against
            # portable_path, which is already case-folded for exactly this reason.
            self.mac_skip_directory = [p.lower() for p in self.mac_skip_directory]
            self.skip_paths = set(self.mac_skip_directory)
        
        else:
            self.lin_skip_directory = []
            self.mac_skip_directory = []
            self.skip_paths = set()


        if self.scan_folder and self.scan_folder.lower() != "default":
            # scan_folder accepts a COMMA-SEPARATED list of locations so one run can cover
            # multiple scopes/partitions (e.g. "C:\Users,D:\Shares" or "/opt/data, /srv/www").
            # A single path (no comma) behaves exactly as before. Entries are validated
            # independently: invalid ones are skipped LOUDLY; if none are valid, fail the scan.
            requested = [p.strip().strip('"').strip("'") for p in self.scan_folder.split(",")]
            requested = [p for p in requested if p]
            valid, invalid = [], []
            for p in requested:
                if os.path.isdir(p):
                    ap = os.path.abspath(p)
                    if ap not in valid:
                        valid.append(ap)
                else:
                    invalid.append(p)
            if not valid:
                raise ValueError(
                    f"No valid scan directory among the specified scan folder(s): {requested}")
            if invalid:
                self.error_logger.error_logger.warning(
                    f"Ignoring {len(invalid)} specified scan folder(s) that are not valid "
                    f"directories on this endpoint: {invalid}")
            self.scan_targets = valid
            self.error_logger.error_logger.info(
                f"Scan limited to {len(valid)} folder(s): {valid}")
        else:
            if hasattr(self, "_discover_all_targets"):
                self.scan_targets = self._discover_all_targets()
            else:
                self.scan_targets = self._default_discover_targets()
            self.error_logger.error_logger.info(f"Scanning default targets: {self.scan_targets}")
            
    def _default_discover_targets(self):
        """Discover default scan targets based on platform and privileges."""
        targets = []
        if platform.system() == "Windows":
            discovered = []

            try:
                for p in psutil.disk_partitions(all=False):
                    mount = (p.mountpoint or "").strip()
                    if mount and os.path.isdir(mount):
                        root = os.path.normpath(mount)
                        if not root.endswith("\\"):
                            root += "\\"
                        discovered.append(root)
            except Exception:
                pass

            try:
                mask = ctypes.windll.kernel32.GetLogicalDrives()
                for i in range(26):
                    if mask & (1 << i):
                        letter = chr(ord("A") + i)
                        root = f"{letter}:\\"
                        try:
                            if os.path.isdir(root):
                                discovered.append(root)
                        except Exception:
                            continue
            except Exception:
                pass

            if not discovered:
                for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    root = f"{letter}:\\"
                    try:
                        if os.path.isdir(root):
                            discovered.append(root)
                    except Exception:
                        continue

            seen = set()
            for root in discovered:
                norm = os.path.normcase(os.path.normpath(root))
                if norm in seen:
                    continue
                seen.add(norm)
                targets.append(root)

            if not targets:
                targets = ["C:\\"]
            self.error_logger.error_logger.info(f"Light profile full-scope targets on Windows: {targets}")

        elif platform.system() == "Linux":
            try:
                is_root = os.geteuid() == 0
            except Exception:
                is_root = False

            if is_root:
                targets = ["/"]
                self.error_logger.error_logger.info("Light profile default scope on Linux: full filesystem")
            else:
                potential_targets = ["/home", "/tmp", "/opt", "/usr/local", "/var/tmp"]
                for target in potential_targets:
                    try:
                        if os.path.exists(target) and os.path.isdir(target) and os.access(target, os.R_OK):
                            targets.append(target)
                    except Exception:
                        continue
                if not targets:
                    targets = ["/"]
                    self.error_logger.error_logger.warning(
                        "Light profile default scope fell back to '/' on Linux - many files may be inaccessible"
                    )
                else:
                    self.error_logger.error_logger.info(
                        f"Light profile default scope on Linux using accessible full-scan targets: {targets}"
                    )

        elif platform.system() == "Darwin":
            try:
                is_root = os.geteuid() == 0
            except Exception:
                is_root = False

            if is_root:
                targets = ["/"]
                self.error_logger.error_logger.info("Light profile default scope on macOS: full filesystem")
                self.error_logger.error_logger.info("Note: SIP restrictions still apply to /System/")
            else:
                potential_targets = [
                    os.path.expanduser("~"), "/Applications",
                    "/Users/Shared", "/usr/local", "/opt"
                ]
                targets = [t for t in potential_targets if os.path.isdir(t) and os.access(t, os.R_OK)]
                if targets:
                    self.error_logger.error_logger.info(
                        f"Light profile default scope on macOS using accessible full-scan targets: {targets}"
                    )
                else:
                    targets = [os.path.expanduser("~")]
                    self.error_logger.error_logger.info(
                        "Light profile default scope on macOS fell back to the user home directory only"
                    )
        
        else:
            targets = []
            self.error_logger.error_logger.warning("Unknown platform - manual target specification required")
                        
        return targets


# ============================================================================
# UPLOAD & COMMUNICATION
# ============================================================================

class ResultsUploader:
    """Real-time YARA match uploader using the standardized webhook payload."""
    
    def __init__(self, config):
        self.config = config
        # NOTE: this uploader deliberately keeps NO local copy of per-offset detail.
        # It used to build one dict per matched offset and hold them all in memory for the
        # whole scan (measured: 1,048,035 offsets -> ~15 GB RSS on one endpoint), to be
        # serialized at the end by save_results(). That write never actually happened -
        # save_results()'s only caller, upload_results(), is never invoked - so the data was
        # accumulated and then discarded. Streaming it to disk was considered and rejected:
        # _write_alerts() already records EVERY offset (String ID / Offset / Data, uncapped)
        # to alert_dir/<rule>.txt, which the evidence ZIP bundles, so a second copy would
        # duplicate an already-large artifact for no new information. The aggregated
        # per-finding upload is unaffected.
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id
        self.date_of_scan = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.log_manager = None

        
        self.upload_queue = Queue()
        self.upload_thread = None
        self.stop_upload_thread = False
        self.upload_stats = {
            'total_matches': 0,
            'successful_uploads': 0,
            'failed_uploads': 0,
            'undelivered': 0,        # items still queued when the drain window expired (never attempted)
        }
        # Rate-limit counters so a sustained upload failure (or a very match-heavy scan) can't
        # bloat the endpoint logs with one line per matched string.
        self._rl_counters = {}
        self._stop_done = False

        if UPLOAD_RESULTS:
            self._start_upload_thread()

    def _throttled_log(self, bucket, msg, level="error", full=20, every=1000):
        """Log the first `full` messages in a bucket, then suppress and emit only a periodic
        running count every `every`. Keeps per-match upload noise from ballooning the log files
        on a sustained failure while still surfacing that something is wrong (and how much)."""
        if not self.log_manager:
            return
        n = self._rl_counters.get(bucket, 0) + 1
        self._rl_counters[bucket] = n
        emit = self.log_manager.log_error if level == "error" else self.log_manager.log_upload
        if n <= full:
            emit(msg)
        elif n == full + 1:
            emit(f"[{bucket}] further similar messages suppressed; will summarize every {every}. "
                 f"Example: {msg[:120]}")
        elif n % every == 0:
            emit(f"[{bucket}] {n} occurrences so far; latest: {msg[:120]}")

    def _start_upload_thread(self):
        """Start background upload thread."""
        if not API_ENDPOINT:
            if self.log_manager:
                self.log_manager.log_upload("API_ENDPOINT not configured - real-time match upload disabled")
            return
            
        if self.log_manager:
            self.log_manager.log_upload("Starting real-time upload thread...")
            
        self.upload_thread = threading.Thread(target=self._upload_worker, daemon=True)
        self.upload_thread.start()
        
        if self.log_manager:
            self.log_manager.log_upload("Real-time upload thread started successfully")

    def _upload_worker(self):
        """Background worker for uploading results.

        Drains the queue before exiting so queued match uploads are not dropped
        at shutdown. Exits only when the sentinel arrives, or when the queue is
        empty AND stop_upload_thread was flipped True by stop().
        """
        if self.log_manager:
            self.log_manager.log_upload("Upload worker thread started")

        while True:
            try:
                standard_log = self.upload_queue.get(timeout=1.0)

                if standard_log is None:
                    break

                # Take everything already queued behind this item and send it as ONE
                # NDJSON request. One POST per finding could not keep up with a storm
                # scan: 23,223 findings x ~756 ms is ~4.9 hours, so 97% were still
                # queued when the drain expired and were counted undelivered.
                batch, saw_sentinel = _collect_batch(self.upload_queue, standard_log)
                self._upload_batch(batch)
                for _ in batch:
                    self.upload_queue.task_done()
                if saw_sentinel:
                    break

            except Empty:
                if self.stop_upload_thread:
                    break
                continue
            except Exception as e:
                err_type = type(e).__name__
                err_text = f"{err_type}: {str(e)}" if str(e) else err_type
                if self.log_manager:
                    self.log_manager.log_error(f"Upload worker unexpected error: {err_text}")
                continue

        if self.log_manager:
            self.log_manager.log_upload("Upload worker thread stopped")

    def _upload_batch(self, items):
        """Upload a batch of match events as NDJSON, with bounded retries.

        Accounting is per EVENT, not per request: a failed batch counts all of its
        events as failed. Counting a rejected 500-event request as a single failure
        would under-report loss by the batch size, which is exactly the kind of
        dishonest bookkeeping the delivery-shortfall reporting exists to prevent.
        """
        if not items:
            return True
        endpoint = _get_webhook_endpoint(API_ENDPOINT)
        n = len(items)

        attempt = 0
        while attempt < MAX_RETRIES_PER_ITEM:
            attempt += 1
            try:
                resp = _post_ndjson(endpoint, API_KEY, items)
                if 200 <= resp.status_code < 300:
                    self.upload_stats['successful_uploads'] += n
                    self._throttled_log("upload_ok",
                                        f"YARA match batch uploaded: {n} event(s) (HTTP {resp.status_code})",
                                        level="upload")
                    return True

                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    delay = _exp_backoff_delay(attempt)
                    self._throttled_log("upload_retry",
                                        f"Batch upload failed (HTTP {resp.status_code}). Retrying in {delay:.1f}s "
                                        f"(attempt {attempt}/{MAX_RETRIES_PER_ITEM}, {n} event(s)).",
                                        level="upload")
                    time.sleep(delay)
                    continue

                self.upload_stats['failed_uploads'] += n
                self._throttled_log("upload_err",
                                    f"YARA match batch failed (HTTP {resp.status_code}, {n} event(s)): "
                                    f"{resp.text[:200]}")
                return False

            except (requests.Timeout, requests.ConnectionError) as e:
                delay = _exp_backoff_delay(attempt)
                self._throttled_log("upload_neterr",
                                    f"Batch upload network error ({type(e).__name__}). Retrying in {delay:.1f}s "
                                    f"(attempt {attempt}/{MAX_RETRIES_PER_ITEM}, {n} event(s)).",
                                    level="upload")
                time.sleep(delay)
            except Exception as e:
                self.upload_stats['failed_uploads'] += n
                self._throttled_log("upload_err",
                                    f"YARA match batch error ({type(e).__name__}: {e}, {n} event(s))")
                return False

        self.upload_stats['failed_uploads'] += n
        self._throttled_log("upload_err",
                            f"YARA match batch exhausted retries ({n} event(s) not delivered)")
        return False

    def stop(self, wait=True):
        """Stop uploader thread with timeout. Idempotent — a second call (main()'s finally
        safety-net after cleanup already stopped us) returns immediately instead of re-paying
        a full drain window."""
        if self._stop_done:
            return
        self._stop_done = True
        try:
            if wait and self.upload_thread and self.upload_thread.is_alive():
                start_wait = time.time()
                initial_queue_size = self.upload_queue.qsize()
                max_wait_time = _compute_drain_budget(initial_queue_size)
                if initial_queue_size > 0 and self.log_manager:
                    self.log_manager.log_upload(
                        f"Waiting for {initial_queue_size} pending match uploads (max {max_wait_time:.0f}s)..."
                    )
                while self.upload_queue.qsize() > 0 and (time.time() - start_wait) < max_wait_time:
                    time.sleep(0.2)

            self.stop_upload_thread = True
            try:
                self.upload_queue.put(None, timeout=0.2)
            except Exception:
                pass

            if wait and self.upload_thread and self.upload_thread.is_alive():
                self.upload_thread.join(timeout=THREAD_CLEANUP_TIMEOUT)
                if self.upload_thread.is_alive() and self.log_manager:
                    self.log_manager.log_upload(f"Upload thread did not terminate within {THREAD_CLEANUP_TIMEOUT}s timeout")
                elif self.log_manager:
                    self.log_manager.log_upload("Upload thread terminated successfully")

            # Honest books: whatever is still queued was never attempted — count it so
            # "0 failed" can't read as fully-delivered while items sit stranded.
            leftover = self.upload_queue.qsize()
            if self.upload_thread and not self.upload_thread.is_alive():
                leftover = 0
                try:
                    while True:
                        item = self.upload_queue.get_nowait()
                        if item is not None:
                            leftover += 1
                except Empty:
                    pass
            else:
                leftover = max(0, leftover - 1)  # approx: minus our sentinel
            if leftover:
                self.upload_stats['undelivered'] += leftover
            s = self.upload_stats
            if self.log_manager:
                self.log_manager.log_upload(
                    f"Match delivery final: matches={s['total_matches']} ok={s['successful_uploads']} "
                    f"failed={s['failed_uploads']} undelivered={s['undelivered']}")
                if s['undelivered']:
                    self.log_manager.log_error(
                        f"{s['undelivered']} match upload(s) undelivered within the drain window "
                        f"(counted in upload stats, not silently dropped)")
        except Exception as e:
            if self.log_manager:
                self.log_manager.log_error(f"Error stopping results uploader: {e}")

    def add_match(self, filename, rule, match_data, file_sha256=None, file_creation_time=None, fallback_detail=None):
        """Add YARA match and queue for upload.

        Grain split (ported from the XDR edition): the UPLOAD gets ONE ITEM PER (rule, file)
        finding, with every matched offset folded into that one item as a capped sample, rather
        than emitted as its own upload. Per-offset detail is not retained here at all - the
        alert files under alert_dir/ already record every offset
        (local, unbounded) - only the network representation is aggregated+sampled.
        """
        raw_matches = list(match_data or [])
        fallback_text = str(fallback_detail or "").strip()
        upload_entries = raw_matches or [
            (None, None, fallback_text or "Condition-only YARA match; no string instances were produced.")
        ]
        match_count = 0
        is_rule_only_match = len(upload_entries) == 1 and upload_entries[0][0] is None and upload_entries[0][1] is None
        _first_offset = None
        _first_string = ""
        _offsets_sample = []
        _strings_sample = []
        _match_id_counts = {}   # true per-string-identifier counts across every offset, uncapped

        for string_id, offset, string_data in upload_entries:
            if string_data is None:
                string_data = ""
            else:
                string_data = _render_match_data(string_data)


            self.upload_stats['total_matches'] += 1
            match_count += 1

            match_key = "" if string_id is None else str(string_id)
            _match_id_counts[match_key] = _match_id_counts.get(match_key, 0) + 1
            if _first_offset is None:
                _first_offset = offset
                _first_string = string_data
            if len(_offsets_sample) < MAX_MATCH_SAMPLES_PER_FINDING:
                _offsets_sample.append("" if offset is None else str(offset))
                _strings_sample.append(string_data)

        truncated = match_count > len(_offsets_sample)

        if UPLOAD_RESULTS and self.upload_thread and self.upload_thread.is_alive():
            try:
                standard_log = create_standard_log(
                    log_type='yara_match',
                    hostname=self.hostname,
                    os_info=self.os_info,
                    ip_address=self.ip_address,
                    scan_id=self.scan_id,
                    message=(
                        f"YARA rule-only match: rule '{rule}' in {filename}"
                        if is_rule_only_match
                        else f"YARA match: rule '{rule}' in {filename} ({match_count} string hit(s))"
                    ),
                    level="INFO",
                    data={
                        'filename': filename,
                        'rule': rule,
                        # Flattened aliases matching the "Yara Matches" dashboard's actual
                        # column names (rule_id/file_name) - the dashboard queries these
                        # exact names in every widget, and never matches on rule/filename.
                        'file_name': filename,
                        'rule_id': rule,
                        'threat_level': getattr(self.config, "alert_severity", "low"),
                        'string': _first_string,
                        'offset': "" if _first_offset is None else str(_first_offset),
                        'match_scope': "rule" if is_rule_only_match else "string",
                        'match_count': match_count,
                        'offsets': json.dumps(_offsets_sample),
                        'strings': json.dumps(_strings_sample),
                        'match_ids': json.dumps(_match_id_counts),
                        'truncated': truncated,
                        'string_match_count': len(raw_matches),
                        'dateOfScan': self.date_of_scan,
                        'file_sha256': file_sha256,
                        'file_creation_time': file_creation_time
                    }
                )
                self.upload_queue.put(standard_log, timeout=1.0)
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"Queued finding for upload: rule='{rule}', file={filename}, "
                        f"hits={match_count}" + (" (truncated)" if truncated else "")
                    )
            except Exception:
                if self.log_manager:
                    self.log_manager.log_upload("Upload queue full - skipping real-time upload for finding")

        if self.log_manager:
            self.log_manager.log_upload(
                f"Added {match_count} local result entries for rule '{rule}' in file: {filename} "
                f"(1 upload item, {len(_offsets_sample)} of {match_count} sampled)"
            )

    def upload_results(self):
        """Finalize upload process with timeout protection."""
        if self.log_manager:
            self.log_manager.log_upload("FINALIZING UPLOAD PROCESS")
        
        if self.upload_thread and self.upload_thread.is_alive():
            if self.log_manager:
                self.log_manager.log_upload("Stopping real-time upload thread...")
            
            start_wait = time.time()
            initial_queue_size = self.upload_queue.qsize()
            max_wait_time = _compute_drain_budget(initial_queue_size)

            if initial_queue_size > 0 and self.log_manager:
                self.log_manager.log_upload(f"Waiting for {initial_queue_size} pending uploads (max {max_wait_time:.0f}s)...")

            while (self.upload_queue.qsize() > 0 and
                time.time() - start_wait < max_wait_time):
                time.sleep(0.5)
            
            final_queue_size = self.upload_queue.qsize()
            if final_queue_size > 0 and self.log_manager:
                self.log_manager.log_upload(
                    f"Timeout reached - {final_queue_size} uploads still pending, proceeding with shutdown"
                )
            elif initial_queue_size > 0 and self.log_manager:
                self.log_manager.log_upload("All pending uploads completed successfully")
            
            self.stop_upload_thread = True
            try:
                self.upload_queue.put(None, timeout=1.0)
            except Exception:
                pass
            
            self.upload_thread.join(timeout=THREAD_CLEANUP_TIMEOUT)
            
            if self.upload_thread.is_alive() and self.log_manager:
                self.log_manager.log_upload(f"Upload thread did not stop within {THREAD_CLEANUP_TIMEOUT}s timeout")
            elif self.log_manager:
                self.log_manager.log_upload("Upload thread stopped successfully")
        
        if self.log_manager:
            self.log_manager.log_upload("UPLOAD STATISTICS")
            self.log_manager.log_upload(f"Total matches found: {self.upload_stats['total_matches']}")
            self.log_manager.log_upload(f"Successful uploads: {self.upload_stats['successful_uploads']}")
            self.log_manager.log_upload(f"Failed uploads: {self.upload_stats['failed_uploads']}")
            
            if self.upload_stats['total_matches'] > 0:
                success_rate = (self.upload_stats['successful_uploads'] / self.upload_stats['total_matches']) * 100
                self.log_manager.log_upload(f"Upload success rate: {success_rate:.1f}%")
        
        
        if self.log_manager:
            if UPLOAD_RESULTS:
                self.log_manager.log_upload(f"Real-time upload completed: {self.upload_stats['successful_uploads']}/{self.upload_stats['total_matches']} successful")
            else:
                self.log_manager.log_upload(f"Upload disabled - {self.upload_stats['total_matches']} matches saved locally")

    def get_upload_stats(self):
        """Get current upload statistics."""
        return self.upload_stats.copy()


class ScanStatusUploader:
    """Periodic scan status uploader.

    Every set_status() call emits a scan_status event through the existing
    webhook_uploader queue (async, batched). webhook_uploader is wired on by
    main() after construction; if absent, set_status falls back to updating
    self.scan_status silently.
    """

    def __init__(self, config):
        self.config = config
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id
        self.scan_start_time = datetime.datetime.now(datetime.timezone.utc)
        self.scan_status = "starting"
        self.webhook_uploader = None  # set by main() after construction

    def upload_scan_status(self, scanner_stats=None):
        """Build and queue a scan_status event via the shared webhook uploader.

        Async (non-blocking); falls back to a no-op if webhook_uploader is
        not configured or telemetry uploads are disabled.
        """
        if not UPLOAD_RESULTS or not UPLOAD_NON_MATCH_DATA or not API_ENDPOINT:
            return
        if not self.webhook_uploader:
            return

        current_time = datetime.datetime.now(datetime.timezone.utc)
        elapsed_time = (current_time - self.scan_start_time).total_seconds()

        status_data = {
            "scan_id": self.scan_id,
            "scan_status": self.scan_status,
            "scan_start_time": self.scan_start_time.isoformat(),
            "current_time": current_time.isoformat(),
            "elapsed_time_seconds": int(elapsed_time),
            "elapsed_time_formatted": str(datetime.timedelta(seconds=int(elapsed_time)))
        }

        if scanner_stats:
            status_data.update({
                "files_scanned": scanner_stats.get('files_scanned', 0),
                "files_skipped": scanner_stats.get('files_skipped', 0),
                "detections_found": scanner_stats.get('total_detections', 0),
                "current_file": scanner_stats.get('last_scanned_file', 'N/A'),
                "scan_targets": scanner_stats.get('targets', []),
                "valid_rules_count": scanner_stats.get('valid_rules_count', 0),
                "failed_rules_count": scanner_stats.get('failed_rules_count', 0),
            })
            if elapsed_time > 0:
                files_per_second = scanner_stats.get('files_scanned', 0) / elapsed_time
                status_data["scan_rate_files_per_second"] = round(files_per_second, 2)

        try:
            standard_log = create_standard_log(
                log_type='scan_status',
                hostname=self.hostname,
                os_info=self.os_info,
                ip_address=self.ip_address,
                scan_id=self.scan_id,
                message=f"Scan status: {self.scan_status}",
                level="INFO",
                data=status_data
            )
            self.webhook_uploader._queue_standard_upload(standard_log)
        except Exception as e:
            logging.warning(f"Failed to queue scan_status event: {e}")

    def set_status(self, status):
        """Update scan status and emit a scan_status event."""
        self.scan_status = status
        logging.info(f"Scan status changed to: {status}")
        self.upload_scan_status()


class WebhookUploader:
    """Dedicated uploader for statistics and performance data."""
    
    def __init__(self, config, log_manager):
        self.config = config
        self.log_manager = log_manager
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id

        self.upload_queue = Queue()
        self.upload_thread = None
        self.upload_active = True
        self.stop_upload_thread = False
        self.upload_logger = log_manager
        self._circuit = CircuitBreaker()
        
        self.upload_stats = defaultdict(lambda: {
            'total': 0,
            'successful': 0,
            'failed': 0
        })
        
        self.last_upload_by_type = defaultdict(float)
        self.upload_intervals = {
            'performance': 30,
            'statistics': 60,
            'system_resource': 45,
            'worker_stats': 120,
            'time_estimates': 60
        }
        
        if UPLOAD_RESULTS and UPLOAD_NON_MATCH_DATA and API_ENDPOINT:
            self._start_upload_thread()
            self.log_manager.log_upload("WebhookUploader initialized and started")

    def _start_upload_thread(self):
        """Start background webhook upload thread."""
        self.upload_thread = threading.Thread(target=self._upload_worker, daemon=True)
        self.upload_thread.start()

    def _upload_worker(self):
        """Background worker for uploading webhook data.

        Drains the queue before exiting so telemetry uploads are not dropped at
        shutdown. Exits only when the sentinel arrives, or when the queue is
        empty AND stop_upload_thread was flipped True by stop_uploader().
        """
        self.log_manager.log_upload("Webhook upload worker thread started")

        while True:
            try:
                standard_log = self.upload_queue.get(timeout=WORKER_GET_TIMEOUT_SECS)

                if standard_log is None:
                    self.upload_queue.task_done()
                    break

                # Batch telemetry the same way as matches. Resource snapshots, worker
                # performance rows and scan-progress events are individually small but
                # numerous on a long scan, and each one used to cost a full round trip.
                batch, saw_sentinel = _collect_batch(self.upload_queue, standard_log)
                self._process_standard_batch(batch)
                for _ in batch:
                    self.upload_queue.task_done()
                if saw_sentinel:
                    self.upload_queue.task_done()
                    break

            except Empty:
                if self.stop_upload_thread:
                    break
                continue
            except Exception:
                continue

        self.log_manager.log_upload("Webhook upload worker thread stopped")

    def _process_standard_batch(self, items):
        """Upload a batch of telemetry events as NDJSON, with retries + circuit breaker.

        Per-type accounting is preserved: a mixed batch credits each event against its
        own type, and a failed batch counts every event in it as failed rather than one.
        """
        if not items:
            return
        by_type = defaultdict(int)
        for it in items:
            t = getattr(it, "type", "unknown")
            by_type[t] += 1
            self.upload_stats[t]['total'] += 1

        # Circuit open: put the whole batch back and let it settle.
        if not self._circuit.allow():
            for it in items:
                try:
                    self.upload_queue.put(it, timeout=1.0)
                except Exception:
                    pass
            time.sleep(2.0)
            return

        endpoint = _get_webhook_endpoint(API_ENDPOINT)
        attempt = 0
        sent_ok = False
        while attempt < MAX_RETRIES_PER_ITEM:
            attempt += 1
            try:
                response = _post_ndjson(endpoint, API_KEY, items)
                if 200 <= response.status_code < 300:
                    sent_ok = True
                    self._circuit.on_success()
                    break
                if response.status_code in (408, 429, 500, 502, 503, 504):
                    time.sleep(_exp_backoff_delay(attempt))
                    continue
                self._circuit.on_failure()
                break
            except (requests.Timeout, requests.ConnectionError):
                time.sleep(_exp_backoff_delay(attempt))
            except Exception as e:
                self._circuit.on_failure()
                self.log_manager.log_error(f"Webhook unexpected error for batch: {str(e)}")
                break

        key = 'successful' if sent_ok else 'failed'
        for t, n in by_type.items():
            self.upload_stats[t][key] += n

    def _queue_standard_upload(self, standard_log: StandardLogEntry, priority=False):
        """Queue standardized log entry for upload."""
        if not UPLOAD_NON_MATCH_DATA:
            return
        try:
            if priority:
                self.upload_queue.put(standard_log, timeout=0.1)
            else:
                self.upload_queue.put(standard_log, timeout=1.0)
        except Exception:
            pass

    def upload_statistics_summary(self, stats_data):
        """Upload comprehensive statistics summary."""
        if not self._should_upload('statistics'):
            return
        
        standard_log = create_standard_log(
            log_type='statistics_summary',
            hostname=self.hostname,
            os_info=self.os_info,
            ip_address=self.ip_address,
            scan_id=self.scan_id,
            message="Statistics checkpoint",
            level="INFO",
            data=stats_data
        )
        
        self._queue_standard_upload(standard_log)
        self._mark_uploaded('statistics')

    def _should_upload(self, data_type):
        """Check if enough time has passed for upload."""
        if not UPLOAD_RESULTS or not UPLOAD_NON_MATCH_DATA or not API_ENDPOINT:
            return False
            
        current_time = time.time()
        last_upload = self.last_upload_by_type[data_type]
        interval = self.upload_intervals.get(data_type, 60)
        
        return (current_time - last_upload) >= interval

    def _mark_uploaded(self, data_type):
        """Mark data type as uploaded."""
        self.last_upload_by_type[data_type] = time.time()

    def get_upload_statistics(self):
        """Get comprehensive upload statistics."""
        total_stats = {
            'total_uploads': 0,
            'successful_uploads': 0,
            'failed_uploads': 0,
            'success_rate_percent': 0
        }
        
        detailed_stats = {}
        
        for data_type, stats in self.upload_stats.items():
            total_stats['total_uploads'] += stats['total']
            total_stats['successful_uploads'] += stats['successful']
            total_stats['failed_uploads'] += stats['failed']
            
            success_rate = (stats['successful'] / stats['total'] * 100) if stats['total'] > 0 else 0
            detailed_stats[data_type] = {
                'total': stats['total'],
                'successful': stats['successful'],
                'failed': stats['failed'],
                'success_rate_percent': success_rate
            }
        
        if total_stats['total_uploads'] > 0:
            total_stats['success_rate_percent'] = (total_stats['successful_uploads'] / total_stats['total_uploads']) * 100
        
        return {
            'summary': total_stats,
            'by_type': detailed_stats,
            'queue_size': self.upload_queue.qsize()
        }

    def stop_uploader(self):
        """Stop webhook uploader with timeout. Idempotent — repeated calls return at once."""
        if getattr(self, "_stop_done", False):
            return
        self._stop_done = True
        try:
            if self.upload_thread and self.upload_thread.is_alive():
                start_wait = time.time()
                initial_queue_size = self.upload_queue.qsize()
                max_wait_time = _compute_drain_budget(initial_queue_size)
                if initial_queue_size > 0:
                    self.log_manager.log_upload(
                        f"Waiting for {initial_queue_size} pending telemetry uploads (max {max_wait_time:.0f}s)..."
                    )
                while self.upload_queue.qsize() > 0 and (time.time() - start_wait) < max_wait_time:
                    time.sleep(0.2)

            self.upload_active = False
            self.stop_upload_thread = True
            try:
                self.upload_queue.put(None, timeout=0.2)
            except Exception:
                pass

            if self.upload_thread and self.upload_thread.is_alive():
                self.upload_thread.join(timeout=THREAD_CLEANUP_TIMEOUT)
                if self.upload_thread.is_alive():
                    self.log_manager.log_upload(f"WARNING: Webhook thread did not terminate within {THREAD_CLEANUP_TIMEOUT}s")
                else:
                    self.log_manager.log_upload("Webhook thread terminated successfully")

            final_stats = self.get_upload_statistics()
            stranded = final_stats.get('queue_size', 0)
            self.log_manager.log_upload(
                f"WebhookUploader stopped. Success rate: {final_stats['summary']['success_rate_percent']:.1f}%"
                + (f" ({stranded} telemetry item(s) undelivered at shutdown)" if stranded else ""),
                final_stats
            )

        except Exception as e:
            if hasattr(self, 'log_manager'):
                self.log_manager.log_upload(f"Error during webhook uploader cleanup: {e}")


# ============================================================================
# EVIDENCE COLLECTION
# ============================================================================

class EvidenceCollector:
    """Collects and packages matched files as evidence."""
    
    def __init__(self, config):
        self.config = config
        self.matched_files = set()
        self.file_hashes = {}

    def add_matched_file(self, file_path, file_sha256=None):
        """Add matched file to collection."""
        self.matched_files.add(file_path)
        if file_sha256:
            self.file_hashes[file_path] = file_sha256

    def collect_evidence(self):
        """Collect and package all evidence."""
        logging.info("Starting evidence collection...")
        self._process_matched_files()
        self._create_evidence_zip()
        logging.info(
            f"Evidence collection completed. Zip file created at: {self.config.evidence_zip}"
        )

    def _process_matched_files(self):
        """Process matched files and calculate hashes."""
        with open(self.config.file_mapping, "w", encoding="utf-8") as mapping_file:
            mapping_file.write("Host Information:\n")
            mapping_file.write(f"Hostname: {self.config.hostname}\n")
            mapping_file.write(f"OS: {self.config.os_info}\n")
            mapping_file.write(f"IP Addresses: {', '.join(self.config.ip_addresses)}\n")
            mapping_file.write("-" * 80 + "\n\n")
            mapping_file.write("Original Path | SHA256 Hash\n")
            mapping_file.write("-" * 80 + "\n")

            for file_path in self.matched_files:
                if os.path.exists(file_path):
                    file_hash = self.file_hashes.get(file_path)
                    if not file_hash:
                        file_hash = FileHasher.calculate_sha256(file_path)
                    if file_hash:
                        self.file_hashes[file_path] = file_hash
                        mapping_file.write(f"{file_path} | {file_hash}\n")

    def _create_evidence_zip(self):
        """Create ZIP file containing evidence.

        Entries are content-addressed (`matched_files/<sha256>`), so several paths
        holding identical bytes collapse to one blob. file_mapping.txt still records
        every path -> hash pair, which is what makes the dedupe lossless.

        Skipping already-packaged hashes is load-bearing, not an optimisation: zipfile
        only *warns* on a repeated arcname and writes the member anyway, so without this
        the archive carried one full copy per duplicate path while readers could still
        only ever see the first. Duplicate files are routine under System32, and this is
        what grew a single scan's archive to gigabytes on the scanned host.
        """
        copy_files = getattr(self.config, "collect_matched_files", COLLECT_MATCHED_FILES)
        packaged_hashes = set()
        duplicates_skipped = 0
        with zipfile.ZipFile(
            self.config.evidence_zip, "w", zipfile.ZIP_DEFLATED
        ) as zip_file:
            if copy_files:
                for file_path, file_hash in self.file_hashes.items():
                    if file_hash in packaged_hashes:
                        duplicates_skipped += 1
                        continue
                    try:
                        zip_file.write(file_path, f"matched_files/{file_hash}")
                        # Only mark packaged after a successful write - if this path
                        # vanished mid-scan, another path with the same content still
                        # deserves a try.
                        packaged_hashes.add(file_hash)
                    except Exception as e:
                        logging.error(f"Error adding file to zip {file_path}: {e}")
            else:
                logging.info(
                    "Evidence: COLLECT_MATCHED_FILES=false - packaging metadata only "
                    "(paths + SHA256 + alert texts, no matched file copies)"
                )

            for alert_file in os.listdir(self.config.alert_dir):
                if alert_file.endswith(".txt"):
                    alert_path = os.path.join(self.config.alert_dir, alert_file)
                    zip_file.write(alert_path, f"alerts/{alert_file}")

            zip_file.write(self.config.file_mapping, "file_mapping.txt")

        if duplicates_skipped:
            logging.info(
                f"Evidence ZIP: {len(packaged_hashes)} unique file(s) packaged, "
                f"{duplicates_skipped} duplicate copy(ies) skipped"
            )


class CleanupManager:
    """Manages cleanup of scan artifacts."""
    
    def __init__(self, config):
        self.config = config

    def _extract_run_id_from_log_name(self, filename):
        """Extract scan run_id from a standardized per-run artefact filename.

        Matches .log, plus scan_summary_<run_id>.json and its .json.tmp orphans - anchoring
        on `\\.log$` alone meant summaries were never retention-managed and accumulated on
        the endpoint indefinitely.
        """
        match = re.search(r'_(\d{8}_\d{6}_\d{6})\.(?:log|json|json\.tmp)$', filename)
        return match.group(1) if match else None

    def _prune_old_scan_logs(self, keep_scans=2):
        """Keep logs for only the latest N scans (by run_id timestamp)."""
        logs_dir = self.config.logs_dir
        if not os.path.isdir(logs_dir):
            return

        run_logs = defaultdict(list)
        for name in os.listdir(logs_dir):
            # Also retain-manage scan_summary_<run_id>.json, not just *.log. It is written
            # once per run into this same directory, so matching only ".log" left every
            # summary ever produced on the endpoint forever - the opposite of what a
            # retention policy is for. Orphaned ".json.tmp" files (a summary write that died
            # mid-dump, e.g. disk full) are swept on the same pass.
            if not (name.endswith(".log") or name.endswith(".json") or name.endswith(".json.tmp")):
                continue
            run_id = self._extract_run_id_from_log_name(name)
            if not run_id:
                continue
            run_logs[run_id].append(os.path.join(logs_dir, name))

        if not run_logs:
            return

        keep_count = max(1, int(keep_scans))
        sorted_run_ids = sorted(run_logs.keys(), reverse=True)
        keep_run_ids = set(sorted_run_ids[:keep_count])
        keep_run_ids.add(self.config.run_id)

        removed = 0
        failed = 0
        for run_id, paths in run_logs.items():
            if run_id in keep_run_ids:
                continue
            for path in paths:
                try:
                    os.remove(path)
                    removed += 1
                except PermissionError:
                    failed += 1
                    logging.warning(f"Cannot remove log file (in use): {path}")
                except OSError as e:
                    failed += 1
                    logging.warning(f"Cannot remove log file {path}: {e}")

        logging.info(
            f"Log retention applied: kept last {keep_count} scans "
            f"({len(keep_run_ids)} run IDs including current), removed {removed} log files"
        )
        if failed:
            logging.warning(f"Log retention: {failed} log files could not be removed")
    
    def initial_cleanup(self):
        """Clean up old data before scan."""
        try:
            logging.info("Starting initial cleanup of old data...")
            
            paths_to_clean = [
                self.config.alert_dir,
                self.config.evidence_dir,
                self.config.output_log,
            ]
            
            cleanup_failed = False
            for path in paths_to_clean:
                if os.path.exists(path):
                    try:
                        if os.path.isfile(path):
                            os.remove(path)
                        else:
                            shutil.rmtree(path)
                        logging.info(f"Removed: {path}")
                    except PermissionError:
                        logging.warning(f"Cannot remove {path} - may be in use")
                        cleanup_failed = True
                        continue
            
            for directory in [self.config.alert_dir, self.config.evidence_dir, 
                            os.path.dirname(self.config.output_log)]:
                os.makedirs(directory, exist_ok=True)

            self._prune_old_scan_logs(keep_scans=2)
            
            if cleanup_failed:
                logging.warning("Some cleanup operations failed - continuing with scan")
            else:
                logging.info("Initial cleanup completed successfully")
                
        except Exception as e:
            logging.error(f"Error during initial cleanup: {e}")
            logging.warning("Continuing with scan despite cleanup issues")

    def schedule_final_cleanup(self):
        """Schedule final cleanup with error checking."""
        has_critical_errors = False
        
        if hasattr(self.config, 'error_logger'):
            error_logger = self.config.error_logger
            has_critical_errors = (error_logger.has_errors and error_logger.valid_rules_count == 0)
        
        if hasattr(self.config, 'log_manager'):
            log_stats = self.config.log_manager.get_upload_statistics()
            error_ratio = log_stats['by_type'].get('error', 0) / max(log_stats['total_logs'], 1)
            if error_ratio > 0.5:
                has_critical_errors = True
        
        if has_critical_errors:
            if hasattr(self.config, 'log_manager'):
                self.config.log_manager.log_system(
                    "Critical errors detected - skipping cleanup to preserve diagnostic data",
                    {'preserve_logs': True}
                )
            logging.info("Critical YARA processing errors detected - skipping cleanup")
            return
        
        if not self._check_for_alerts():
            if hasattr(self.config, 'log_manager'):
                self.config.log_manager.log_system("No alerts found, skipping cleanup scheduling")
            logging.info("No alerts found, skipping final cleanup scheduling")
            return

        try:
            self._decode_cleanup_script()
            
            if hasattr(self.config, 'log_manager'):
                self.config.log_manager.log_system("Cleanup script decoded and ready for scheduling")
            
            if platform.system() == "Windows":
                self._schedule_windows_cleanup()
                if hasattr(self.config, 'log_manager'):
                    self.config.log_manager.log_system("Windows cleanup task scheduled successfully")
            else:
                self._schedule_linux_cleanup()
                if hasattr(self.config, 'log_manager'):
                    self.config.log_manager.log_system("Linux cleanup service scheduled successfully")
                    
        except Exception as e:
            if hasattr(self.config, 'log_manager'):
                self.config.log_manager.log_error(f"Failed to schedule cleanup: {e}")
            logging.error(f"Error scheduling final cleanup: {e}")
            raise

    def _check_for_alerts(self):
        """Check if any alerts were generated."""
        return any(f.endswith(".txt") for f in os.listdir(self.config.alert_dir))

    def _decode_cleanup_script(self):
        """Decode and write cleanup script."""
        script_content = self._get_cleanup_script_content()
        with open(self.config.cleanup_script, "w", encoding="utf-8") as f:
            f.write(script_content)

        if platform.system() != "Windows":
            os.chmod(self.config.cleanup_script, 0o755)

    def _get_cleanup_script_content(self):
        """Get platform-specific cleanup script."""
        if platform.system() == "Windows":
            return base64.b64decode(b64CleanupScriptWindows).decode("utf-8")
        return base64.b64decode(b64CleanupScriptLinux).decode("utf-8")

    def _schedule_windows_cleanup(self):
        """Schedule cleanup task in Windows."""
        try:
            task_time = (
                datetime.datetime.now() + datetime.timedelta(minutes=1)
            ).strftime("%H:%M")
            
            task_create_cmd = [
                "schtasks", "/create", "/tn", "CleanupScript",
                "/tr", self.config.cleanup_script,
                "/sc", "once", "/st", task_time,
                "/ru", "SYSTEM", "/f"
            ]
            subprocess.run(task_create_cmd, shell=False, check=True)
            logging.info(f"Windows cleanup task scheduled for {task_time}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error scheduling Windows cleanup: {e}")
            raise

    def _schedule_linux_cleanup(self):
        """Schedule cleanup service in Linux."""
        try:
            service_content = f"""[Unit]
Description=YARA Scanner Cleanup Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash {self.config.cleanup_script}
RemainAfterExit=no
User=root

[Install]
WantedBy=multi-user.target
"""
            service_path = "/etc/systemd/system/yara-cleanup.service"
            with open(service_path, "w") as f:
                f.write(service_content)

            if not os.path.exists(service_path):
                raise Exception("Service file was not created successfully")

            service_stat = os.stat(service_path)
            if service_stat.st_uid != 0:
                raise Exception("Service file not owned by root")

            subprocess.run(["systemctl", "daemon-reload"], shell=False, check=True)
            subprocess.run(["systemctl", "enable", "yara-cleanup.service"], shell=False, check=True) 
            subprocess.run(["systemctl", "start", "yara-cleanup.service"], shell=False, check=True)

            logging.info("Linux cleanup service created and started")

        except subprocess.CalledProcessError as e:
            logging.error(f"Error scheduling Linux cleanup: {e}")
            raise


# ============================================================================
# MAIN SCANNING ENGINE
# ============================================================================

class YaraScanner:
    """Main YARA scanning engine with multi-threaded file processing."""
    
    def __init__(self, config, log_manager=None, stats_manager=None):
        self.config = config
        self.fd_monitoring_enabled = getattr(config, 'monitor_fd_usage', False)
        self.initial_fd_count = getattr(config, 'initial_fd_count', 0)
        self.fd_check_interval = 1000
        self.files_since_fd_check = 0
        self.rule_source_map = _build_yara_rule_source_map(config.yara_rule)

        self.log_manager = log_manager if log_manager else LogManager(config)
        self.stats_manager = stats_manager if stats_manager else StatisticsManager(config, self.log_manager)

        # Liveness marker BEFORE rule compilation. Compiling a large ruleset can take a
        # minute or more, and until the marker exists `cancel` reports "scanner running: no"
        # about a scan that is very much alive - which pushes the operator to the console's
        # Cancel button, the destructive hard-kill this whole feature exists to replace.
        # Only the paths/counters the marker writer touches are needed this early.
        _control = getattr(config, "control_dir", config.scanner_dir)
        self.cancel_flag_path = os.path.join(_control, "cancel.flag")
        self.running_marker_path = os.path.join(_control, "running.json")
        self.files_scanned = 0
        self.total_detections = 0
        self.scan_start_time = time.time()
        self._last_marker_refresh = 0.0
        self._write_running_marker("compiling")

        self.rules = self._compile_yara_rules(config.yara_rule)

        self.files_scanned = 0
        self.files_skipped = 0
        self.skip_reasons = defaultdict(int)
        self.last_log_time = time.time()
        self.last_scanned_file = ""
        self.evidence_collector = EvidenceCollector(config)
        self.detection_counts = defaultdict(int)
        self.total_detections = 0
        self.results_uploader = ResultsUploader(config)
        self.lock_counts = threading.Lock()
        self.lock_files = threading.Lock()
        self.lock_alert = threading.Lock()
        self.lock_throttle = threading.Lock()

        self.status_uploader = ScanStatusUploader(config)
        self.results_uploader.log_manager = self.log_manager

        self.scan_queue = Queue(maxsize=self.config.scan_queue_size)
        self.scan_threads = []
        self.scan_active = True
        self.scan_failed = False
        self.failure_reasons = []
        self.lock_failures = threading.Lock()
        self.scan_targets = []
        self.scan_start_time = time.time()

        # Cooperative cancellation state. (cancel_flag_path/running_marker_path are set
        # earlier, before rule compilation, so the liveness marker exists during it.)
        self.cancel_requested = False
        self.cancel_source = ""
        self._cancel_lock = threading.Lock()
        self.cancel_watcher_thread = None
        # Module-import time, NOT time.time() here: this object is constructed AFTER rule
        # compilation, so a self-timestamp would make the staleness check discard a cancel
        # delivered while a large ruleset was still compiling.
        self._process_started_at = _PROCESS_STARTED_AT
        self._last_marker_refresh = 0.0
        
        self.scanned_real_paths = set()
        self.junction_skip_count = 0
        self.lock_real_paths = threading.Lock()

        # Requested scan targets that the skip list excludes wholesale. Without this a
        # target inside the skip list produced outcome="completed", 0 scanned, exit 0 -
        # indistinguishable from an empty directory, so an operator scanning e.g.
        # AppData\Local\Temp got a clean success and zero coverage.
        self.excluded_targets = []
        self.worker_processing_times = defaultdict(list)
        self.last_throttle_check = 0.0
        self.last_system_cpu = 0.0
        self.last_throttle_sleep_secs = 0.0
        self.queue_full_events = 0
        
        self.log_manager.log_system(
            f"YaraScanner initialized with {self.config.max_workers} workers",
            {
                'max_workers': self.config.max_workers,
                'max_file_mb': self.config.max_file_mb,
                'valid_rules': self.config.error_logger.valid_rules_count,
                'failed_rules': self.config.error_logger.failed_rules_count
            }
        )

    def _mark_scan_failed(self, reason: str):
        """Mark scanner state as failed and stop active scanning."""
        with self.lock_failures:
            self.scan_failed = True
            self.failure_reasons.append(reason)
        self.scan_active = False
    
    def _clean_rule_content(self, rule_lines, rule_name):
        """Normalize extracted rule block without mutating braces."""
        if not rule_lines:
            return None
        
        if isinstance(rule_lines, str):
            content = rule_lines.strip()
        else:
            content = '\n'.join(rule_lines).strip()
        
        if not re.match(r'^\s*(?:(?:private|global)\s+)*rule\s+\w+', content, re.IGNORECASE):
            logging.warning(f"Rule {rule_name} doesn't start with 'rule' keyword")
            return None
        return content

    
    def _get_available_yara_modules(self, source_text=None):
        """Detect which YARA modules are available on THIS agent's libyara build.

        The candidate set is the standard probe list UNION every module actually
        imported by the submitted rules. Probing only a hardcoded list meant any
        module outside it was treated as unavailable no matter what libyara really
        supported - so `_split_yara_rules` would strip a perfectly good preamble
        import and the rule would then fail to compile with "undefined identifier".
        Deriving the extra candidates from the source makes this correct for any
        current or future libyara build. (The same hardcoded-list defect exists in
        the XDR edition - see xdr_yara_scanner.py's _get_available_yara_modules.)
        """
        test_modules = ['pe', 'elf', 'cuckoo', 'magic', 'hash', 'math', 'dotnet', 'time']
        if source_text:
            for module in sorted(self._extract_imported_modules(source_text)):
                if module not in test_modules:
                    test_modules.append(module)
        available = []

        for module in test_modules:
            try:
                test_rule = f'''import "{module}"
rule test {{
    condition:
        true
}}'''
                yara.compile(source=test_rule, externals=YARA_COMPILE_EXTERNALS)
                available.append(module)
            except Exception as e:
                logging.debug(f"Module '{module}' not available: {e}")
        
        return available

    def _rule_uses_unavailable_modules(self, rule_content, available_modules):
        """Check if rule imports unavailable modules."""
        for module_name in self._extract_imported_modules(rule_content):
            if module_name not in available_modules:
                logging.debug(f"Rule uses unavailable module: {module_name}")
                return True, module_name

        return False, None

    def _module_missing_from_compile_error(self, error, source_imported_modules, available_modules):
        """Return the module name if a compile error is really "this agent lacks a module".

        A rule that inherits `import "cuckoo"` from a shared PREAMBLE (the normal, idiomatic
        YARA layout) has that import stripped by _split_yara_rules when the module is not
        available on this agent's libyara build. The rule body still references
        `cuckoo.something`, so yara.compile raises `undefined identifier "cuckoo"` and the
        rule would be booked as a COMPILE FAILURE - inflating the failed count, writing a
        bogus failed_rule_*.yar artifact, and making a healthy scan look broken. The check
        above cannot catch this: it only inspects the rule's own text, and after splitting
        there is no import line left there to find.

        Classifying on the actual compile error is deliberate. The XDR edition instead
        gates on a per-module usage REGEX, which over-skips: a rule hunting for the literal
        string "cuckoo.conf" contains `cuckoo.` and would be silently dropped. Requiring
        BOTH that yara itself reported the identifier undefined AND that the name was
        imported somewhere in the original source AND that it is genuinely unavailable
        cannot mis-handle a literal string.
        """
        if not source_imported_modules:
            return None
        text = str(error)
        for module_name in re.findall(r'undefined identifier "(\w+)"', text):
            if module_name in source_imported_modules and module_name not in available_modules:
                return module_name
        return None

    def _extract_imported_modules(self, source_text):
        """Extract imported YARA module names from a source block."""
        imported = set()
        for statement in _get_yara_top_level_statements(source_text):
            if statement["type"] != "import":
                continue
            match = re.match(r'^\s*import\s+"?(\w+)"?', statement["text"], re.IGNORECASE)
            if match:
                imported.add(match.group(1))
        return imported

    def _inject_missing_rule_imports(self, rule_content, available_modules, preamble_imports=None):
        """Inject missing module imports required by a rule based on module usage."""
        preamble_imports = preamble_imports or set()
        already_imported = self._extract_imported_modules(rule_content) | set(preamble_imports)

        module_usage_patterns = OrderedDict([
            ("math", r"\bmath\."),
            ("elf", r"\belf\."),
            ("pe", r"\bpe\."),
            ("hash", r"\bhash\."),
            ("time", r"\btime\."),
            ("dotnet", r"\bdotnet\."),
            ("magic", r"\bmagic\."),
            ("cuckoo", r"\bcuckoo\."),
        ])

        missing = []
        for module_name, usage_pattern in module_usage_patterns.items():
            if re.search(usage_pattern, rule_content):
                if module_name in available_modules and module_name not in already_imported:
                    missing.append(module_name)

        if not missing:
            return rule_content, []

        import_block = "\n".join(f'import "{m}"' for m in missing)
        return f"{import_block}\n{rule_content}", missing

    def _compile_yara_rules(self, yara_rule_string):
        """Compile YARA rules with robust error handling."""
        error_logger = self.config.error_logger
        available_modules = self._get_available_yara_modules(yara_rule_string)
        logging.info(f"Available YARA modules: {', '.join(available_modules)}")
        error_logger.error_logger.info(f"Available YARA modules: {', '.join(available_modules)}")
        
        if 'cuckoo' not in available_modules:
            logging.warning("YARA cuckoo module not available - rules using it will be skipped")
            error_logger.error_logger.warning("YARA cuckoo module not available")
        
        self._debug_rule_analysis(yara_rule_string)
        
        try:
            preamble, individual_rules = self._split_yara_rules(yara_rule_string, available_modules)
            logging.info(f"Split result: {len(individual_rules)} rules extracted")
        except Exception as e:
            error_logger.has_errors = True
            error_logger.error_logger.error(f"SPLIT_ERROR: Failed to split YARA rules: {e}")
            raise ValueError(f"Failed to split YARA rules: {e}")
        
        if not individual_rules:
            error_msg = "No YARA rules found in provided content"
            error_logger.has_errors = True
            error_logger.error_logger.error(f"COMPILATION_ERROR: {error_msg}")
            try:
                debug_file = os.path.join(self.config.failed_rules_dir, "raw_yara_content.yar")
                with open(debug_file, "w", encoding="utf-8") as f:
                    f.write("// RAW YARA CONTENT - Failed to split into individual rules\n")
                    f.write("// " + "="*70 + "\n\n")
                    f.write(yara_rule_string)
                logging.error(f"Saved raw YARA content to: {debug_file}")
            except Exception:
                pass
            raise ValueError(error_msg)

        valid_sources = {}
        compilation_errors = []
        skipped_count = 0
        preamble_imports = self._extract_imported_modules(preamble)
        # Imports from the RAW source, before _split_yara_rules stripped the unavailable
        # ones out of the preamble. Needed to tell "this agent lacks the module" apart from
        # a genuine syntax error when a split rule fails to compile.
        source_imported_modules = self._extract_imported_modules(yara_rule_string)
        logging.info(f"Starting compilation of {len(individual_rules)} YARA rules...")

        for i, rule_content in enumerate(individual_rules, 1):
            name_match = re.search(r'rule\s+(\w+)', rule_content, re.IGNORECASE)
            display_name = name_match.group(1) if name_match else f"rule_{i}"

            uses_unavailable, missing_module = self._rule_uses_unavailable_modules(
                rule_content, available_modules
            )
            
            if uses_unavailable:
                skipped_count += 1
                if skipped_count <= 10:
                    logging.warning(f"Skipping rule '{display_name}': uses unavailable module '{missing_module}'")
                    error_logger.error_logger.warning(f"Skipping rule '{display_name}': uses unavailable module '{missing_module}'")
                try:
                    skipped_rule_path = os.path.join(
                        self.config.failed_rules_dir, 
                        f"skipped_rule_{display_name}_{missing_module}.yar"
                    )
                    with open(skipped_rule_path, "w", encoding="utf-8") as f:
                        f.write(f"// SKIPPED RULE - Module '{missing_module}' not available\n")
                        f.write(f"// Date: {datetime.datetime.now().isoformat()}\n")
                        f.write("// " + "="*50 + "\n\n")
                        f.write(rule_content)
                except Exception:
                    pass
                continue

            try:
                compiled_rule_content, injected_modules = self._inject_missing_rule_imports(
                    rule_content,
                    available_modules,
                    preamble_imports=preamble_imports
                )
                if injected_modules:
                    msg = f"Auto-injected missing imports for rule '{display_name}': {', '.join(injected_modules)}"
                    logging.info(msg)
                    error_logger.error_logger.info(msg)

                source_with_preamble = (preamble + "\n\n" if preamble else "") + compiled_rule_content
                yara.compile(source=source_with_preamble, externals=YARA_COMPILE_EXTERNALS)
                
                valid_sources[f"ns_{i}_{display_name}"] = source_with_preamble
                error_logger.valid_rules_count += 1
                
                if i % 50 == 0:
                    logging.info(f"✓ Compiled {i}/{len(individual_rules)} rules ({error_logger.valid_rules_count} valid, {error_logger.failed_rules_count} failed, {skipped_count} skipped)")

            except Exception as e:
                # Not a compile failure: the rule needs a module this agent's libyara
                # does not have, inherited from a preamble import that was stripped.
                _missing = self._module_missing_from_compile_error(
                    e, source_imported_modules, available_modules
                )
                if _missing:
                    skipped_count += 1
                    if skipped_count <= 10:
                        msg = (f"Skipping rule '{display_name}': needs unavailable module "
                               f"'{_missing}' (inherited from a file-level import)")
                        logging.warning(msg)
                        error_logger.error_logger.warning(msg)
                    try:
                        skipped_rule_path = os.path.join(
                            self.config.failed_rules_dir,
                            f"skipped_rule_{display_name}_{_missing}.yar"
                        )
                        with open(skipped_rule_path, "w", encoding="utf-8") as f:
                            f.write(f"// SKIPPED RULE - Module '{_missing}' not available on this agent\n")
                            f.write(f"// (import inherited from the file-level preamble)\n")
                            f.write(f"// Date: {datetime.datetime.now().isoformat()}\n")
                            f.write("// " + "="*50 + "\n\n")
                            f.write(rule_content)
                    except Exception:
                        pass
                    continue

                compilation_errors.append(f"Rule {display_name}: {str(e)}")
                error_logger.log_rule_compilation_error(display_name, rule_content, e)

                if error_logger.failed_rules_count <= 10:
                    logging.warning(f"Failed rule {display_name}: {str(e)[:100]}")
                
                try:
                    failed_rule_path = os.path.join(
                        self.config.failed_rules_dir, 
                        f"failed_rule_{display_name}.yar"
                    )
                    with open(failed_rule_path, "w", encoding="utf-8") as f:
                        f.write("// FAILED RULE - Compilation Error\n")
                        f.write(f"// Error: {str(e)}\n")
                        f.write(f"// Date: {datetime.datetime.now().isoformat()}\n")
                        f.write("// " + "="*50 + "\n\n")
                        if preamble:
                            f.write(preamble + "\n\n")
                        f.write(rule_content)
                except Exception:
                    pass

        error_logger.log_compilation_summary()
        
        logging.info(f"Compilation complete: {error_logger.valid_rules_count} valid, {error_logger.failed_rules_count} failed, {skipped_count} skipped")

        # Publish on the error_logger so main() can surface it on the SCAN_RESULT line and
        # in scan_summary_<run_id>.json - local logs alone are not an operator-visible
        # channel for an Action Center run.
        error_logger.skipped_rules_count = skipped_count
        if skipped_count > 0:
            error_logger.error_logger.info(f"Skipped {skipped_count} rules due to unavailable modules")

        if not valid_sources:
            # Distinguish "your rules are broken" from "this agent's libyara cannot run
            # them". Both end the scan, but they need completely different responses, and
            # reporting an all-skipped pack as a compilation failure sends the operator
            # hunting for a syntax error that does not exist.
            if skipped_count and not error_logger.failed_rules_count:
                error_msg = (
                    f"No rules could run on this endpoint: all {skipped_count} rule(s) need "
                    f"YARA modules this agent's libyara build does not provide "
                    f"(available: {', '.join(available_modules) or 'none'}). "
                    f"This is an agent capability limit, not a rule syntax error."
                )
            else:
                error_msg = f"No valid YARA rules could be compiled out of {len(individual_rules)} rules."
            error_logger.has_errors = True
            error_logger.error_logger.error(f"FINAL_COMPILATION_ERROR: {error_msg}")
            sys.stderr.write(f"CRITICAL: YARA rule compilation failed: {error_msg}\n")
            sys.stderr.write(f"Valid rules: {error_logger.valid_rules_count}, Failed rules: {error_logger.failed_rules_count}, Skipped: {skipped_count}\n")
            sys.stderr.flush()
            raise ValueError(error_msg)

        try:
            compiled = yara.compile(sources=valid_sources, externals=YARA_COMPILE_EXTERNALS)

            success_msg = f"Successfully built ruleset with {len(valid_sources)} rules"
            if compilation_errors:
                success_msg += f" ({len(compilation_errors)} failed)"
            if skipped_count > 0:
                success_msg += f" ({skipped_count} skipped - missing modules)"

            logging.info(success_msg)
            return compiled
            
        except Exception as e:
            error_logger.has_errors = True
            error_logger.error_logger.error(f"COMBINED_COMPILATION_ERROR: {e}")
            raise

    def _split_yara_rules(self, yara_rule_string, available_modules=None):
        """Split YARA rules robustly using rule boundaries."""
        statements = _get_yara_top_level_statements(yara_rule_string)
        
        imports = []
        imports_seen = set()
        for statement in statements:
            if statement["type"] not in ("import", "include"):
                continue

            stripped = statement["text"].strip()
            if stripped in imports_seen:
                continue

            if available_modules is not None:
                import_match = re.search(r'import\s+"([^"]+)"', stripped, re.IGNORECASE)
                if import_match:
                    module_name = import_match.group(1)
                    if module_name in available_modules:
                        imports.append(stripped)
                        imports_seen.add(stripped)
                    else:
                        logging.debug(f"Skipping unavailable module in preamble: {module_name}")
                else:
                    imports.append(stripped)
                    imports_seen.add(stripped)
            else:
                imports.append(stripped)
                imports_seen.add(stripped)
                        
        logging.info(f"Found {len(imports)} unique import statements")
        
        rule_starts = []
        for statement in statements:
            if statement["type"] == "rule":
                rule_name = statement["name"] or f"rule_{len(rule_starts)+1}"
                rule_starts.append((statement["start"], rule_name, statement["text"]))
        
        logging.info(f"Found {len(rule_starts)} rule start positions")
        
        rules = []
        successful_extractions = 0
        failed_extractions = 0
        
        for _start_pos, rule_name, rule_text in rule_starts:
            try:
                rule_content = self._clean_rule_content(rule_text, rule_name)
                
                if rule_content:
                    rules.append(rule_content)
                    successful_extractions += 1
                    
                    if successful_extractions % 100 == 0:
                        logging.info(f"Extracted {successful_extractions} rules...")
                else:
                    failed_extractions += 1
                    logging.warning(f"Failed to extract rule: {rule_name}")
                    
            except Exception as e:
                failed_extractions += 1
                logging.error(f"Error extracting rule {rule_name}: {e}")
        
        logging.info(f"Rule extraction complete: {successful_extractions} successful, {failed_extractions} failed")
        
        sample_count = min(10, len(rules))
        if sample_count > 0:
            logging.info(f"Sample of first {sample_count} extracted rules:")
            for i, rule in enumerate(rules[:sample_count]):
                rule_name_match = re.search(r'rule\s+(\w+)', rule, re.IGNORECASE)
                rule_name = rule_name_match.group(1) if rule_name_match else f"unnamed_{i+1}"
                logging.info(f"  {i+1}. {rule_name}")
        
        return '\n'.join(imports).strip(), rules

    def _worker(self):
        """Worker thread for file scanning."""
        worker_id = threading.current_thread().name
        files_processed = 0
        errors_encountered = 0
        
        self.log_manager.log_system(f"Worker {worker_id} started")
        
        try:
            while self.scan_active:
                try:
                    fp = self.scan_queue.get(timeout=5.0)
                    if fp is None:
                        self.scan_queue.task_done()
                        break
                    scanned, reason = self.scan_file(fp)
                    
                    with self.lock_counts:
                        if scanned:
                            self.files_scanned += 1
                            files_processed += 1
                        else:
                            self.files_skipped += 1
                            if reason not in self.skip_reasons:
                                self.skip_reasons[reason] = 0
                            self.skip_reasons[reason] += 1
                        self.last_scanned_file = fp
                    
                    if files_processed % 100 == 0 and files_processed > 0:
                        avg_time_ms = sum(self.worker_processing_times[worker_id]) / len(self.worker_processing_times[worker_id]) * 1000
                        error_rate = (errors_encountered / files_processed) * 100
                        
                        self.log_manager.log_worker_performance(
                            worker_id, files_processed, avg_time_ms, error_rate
                        )
                    self.scan_queue.task_done()
                except Empty:
                    continue
                except Exception as e:
                    error_str = str(e)
                    if error_str and "Empty" not in error_str:
                        exception_type = type(e).__name__
                        sys.stderr.write(f"Worker {worker_id} critical error: {exception_type}: {error_str}\n")
                        self.log_manager.log_error(f"Worker {worker_id} error: {exception_type}: {error_str}")
                        errors_encountered += 1
                    continue                    
                        
        except Exception as e:
            fatal_msg = f"Worker {worker_id} fatal error: {e}"
            self.log_manager.log_error(fatal_msg)
            self._mark_scan_failed(fatal_msg)
        finally:
            avg_time = 0
            if files_processed > 0 and worker_id in self.worker_processing_times:
                avg_time = sum(self.worker_processing_times[worker_id]) / len(self.worker_processing_times[worker_id])
            
            self.log_manager.log_system(
                f"Worker {worker_id} stopped",
                {
                    'files_processed': files_processed,
                    'errors_encountered': errors_encountered,
                    'average_processing_time_ms': avg_time * 1000
                }
            )
    


    def _maybe_throttle_scanning(self, force=False):
        """Apply a small pause when the machine is already under CPU pressure."""
        if not getattr(self.config, "light_throttle_enabled", False):
            return

        sleep_for = 0.0
        now = time.time()
        with self.lock_throttle:
            if (not force and
                (now - self.last_throttle_check) < self.config.throttle_check_interval_secs):
                sleep_for = self.last_throttle_sleep_secs
            else:
                self.last_throttle_check = now
                self.last_system_cpu = 0.0
                self.last_throttle_sleep_secs = 0.0
                try:
                    self.last_system_cpu = psutil.cpu_percent(interval=None)
                    if self.last_system_cpu >= self.config.critical_cpu_threshold:
                        self.last_throttle_sleep_secs = self.config.critical_throttle_sleep_secs
                    elif self.last_system_cpu >= self.config.high_cpu_threshold:
                        self.last_throttle_sleep_secs = self.config.throttle_sleep_secs
                except Exception:
                    self.last_system_cpu = 0.0
                sleep_for = self.last_throttle_sleep_secs

        if sleep_for > 0:
            time.sleep(sleep_for)

    def _enqueue_scan_path(self, path):
        """Block gently when workers are saturated instead of dropping files."""
        while self.scan_active:
            try:
                self.scan_queue.put(path, timeout=1.0)
                return True
            except Full:
                self.queue_full_events += 1
                if self.queue_full_events % 25 == 1:
                    self.log_manager.log_performance(
                        f"Scan queue saturated ({self.scan_queue.qsize()} items) - backing off producer"
                    )
                self._maybe_throttle_scanning(force=True)
                time.sleep(self.config.queue_backoff_secs)
            except Exception as e:
                self.log_manager.log_error(f"Failed to enqueue file for scanning: {e}", {'file_path': path})
                return False
        return False

    def _calculate_match_sha256(self, file_path):
        """Hash only matched files to avoid a full-file read on every scan."""
        try:
            return _sha256_file(file_path)
        except Exception as e:
            self.log_manager.log_error(
                f"Failed to hash matched file {file_path}: {e}",
                {'file_path': file_path, 'error': str(e)}
            )
            return None
            
    def scan_file(self, file_path):
        """Scan single file with YARA rules."""
        worker_start_time = time.time()
        worker_id = threading.current_thread().name
        error_occurred = False
        real_path = file_path
        file_creation_time = None
        
        try:
            if not os.path.exists(file_path):
                return False, "File does not exist"

            if not os.access(file_path, os.R_OK):
                try:
                    file_stat = os.stat(file_path)
                    owner_uid = file_stat.st_uid
                    file_mode = oct(file_stat.st_mode)
                    
                    permission_info = {
                        'file_path': file_path,
                        'file_mode': file_mode,
                        'owner_uid': owner_uid,
                        'scanner_uid': os.getuid() if platform.system() != "Windows" else None,
                        'requires_root': owner_uid == 0 or file_path.startswith(('/etc', '/boot', '/var/log', '/root'))
                    }
                    
                    if hasattr(self, 'log_manager'):
                        self.log_manager.log_system(f"Permission denied: {file_path}", permission_info)
                        
                    if not hasattr(self, 'permission_denials'):
                        self.permission_denials = []
                    self.permission_denials.append(permission_info)
                    
                except Exception:
                    pass
                    
                return False, "No read permission"

            if self._is_special_file(file_path):
                return False, "Special system file"

            real_path = _get_real_path(file_path)
            if self.config.track_real_paths:
                with self.lock_real_paths:
                    if real_path in self.scanned_real_paths:
                        return False, "Junction/symlink duplicate"

            st = os.stat(file_path)
            if not stat.S_ISREG(st.st_mode):
                return False, "Not a regular file"

            max_bytes = self.config.max_file_bytes
            if max_bytes and st.st_size > max_bytes:
                return False, "File too large"

            if self.config.track_real_paths:
                with self.lock_real_paths:
                    self.scanned_real_paths.add(real_path)

            self._maybe_throttle_scanning()
            matches = self.rules.match(
                filepath=file_path,
                externals=_build_yara_match_externals(file_path),
                callback=self._yara_callback,
            )

            if matches:
                file_creation_time = _get_file_creation_time_iso(file_path, st)
                content_hash = self._calculate_match_sha256(file_path)
                _alert_detail = self._write_alerts(
                    matches,
                    file_path,
                    file_sha256=content_hash,
                    file_creation_time=file_creation_time
                ) or {}
                with self.lock_files:
                    self.evidence_collector.add_matched_file(file_path, file_sha256=content_hash)
                
                # ONE alert per matched file, carrying the union of what used to be two
                # separate events (see _write_alerts). rules_triggered is kept as an alias
                # of rules_matched so either field name still resolves for anyone who built
                # an ad-hoc query against the old shape.
                _rules = [_iter_hit_fields(m)[0] for m in matches]
                self.log_manager.log_alert(
                    f"YARA matches found in {file_path} "
                    f"({len(matches)} rule(s), {_alert_detail.get('total_string_matches', 0)} string hit(s))",
                    {
                        'file_path': file_path,
                        'real_path': real_path,
                        'file_size': st.st_size,
                        'file_sha256': content_hash,
                        'file_creation_time': file_creation_time,
                        'match_count': len(matches),
                        'rules_matched': _rules,
                        'rules_triggered': _rules,
                        'total_string_matches': _alert_detail.get('total_string_matches', 0),
                        'detections': _alert_detail.get('detections', []),
                        'detection_timestamp': _alert_detail.get('detection_timestamp'),
                    }
                )
                return True, "Scanned and matched"

            if self.fd_monitoring_enabled:
                self.files_since_fd_check += 1
                if self.files_since_fd_check >= self.fd_check_interval:
                    self.files_since_fd_check = 0
                    try:
                        if platform.system() != "Windows":
                            try:
                                current_process = psutil.Process()
                                if hasattr(current_process, 'num_fds'):
                                    current_fds = current_process.num_fds()
                                    fd_increase = current_fds - self.initial_fd_count
                                    
                                    if fd_increase > 100:
                                        self.log_manager.log_system(
                                            f"FD usage increased by {fd_increase} (current: {current_fds})"
                                        )
                                        
                                    if current_fds > 900:
                                        self.log_manager.log_system(
                                            f"WARNING: High FD usage: {current_fds}"
                                        )
                            except Exception:
                                pass
                                    
                    except Exception:
                        pass

            return True, "Scanned but not matched"
            
        except PermissionError:
            error_occurred = True
            return False, "Permission denied"
        except Exception as e:
            error_occurred = True
            sys.stderr.write(f"File scan error: {file_path} - {str(e)}\n")
            self.log_manager.log_error(
                f"Error scanning file {file_path}: {str(e)}",
                {'file_path': file_path, 'real_path': real_path, 'error': str(e)}
            )
            return False, _scan_error_reason(e)
        finally:
            processing_time = time.time() - worker_start_time
            self.stats_manager.update_worker_stats(worker_id, processing_time, error_occurred)
            
            self.worker_processing_times[worker_id].append(processing_time)
            if len(self.worker_processing_times[worker_id]) > 100:
                self.worker_processing_times[worker_id] = self.worker_processing_times[worker_id][-100:]

    def _yara_callback(self, data):
        """Callback function for YARA matches."""
        if data.get("matches"):
            return yara.CALLBACK_CONTINUE
        return yara.CALLBACK_CONTINUE

    def _is_special_file(self, path):
        """Check if file should be skipped."""
        if platform.system() == "Windows":
            normalized_path = os.path.normpath(path.lower())
        else:
            normalized_path = os.path.normpath(path)
            
        scanner_log_path = (
            os.path.normpath(self.config.output_log.lower())
            if platform.system() == "Windows"
            else self.config.output_log
        )
        if normalized_path == scanner_log_path:
            return True

        portable_path = normalized_path.replace("\\", "/").lower()
        filename = os.path.basename(portable_path)
        if filename in self.config.skip_filenames:
            return True
        if any(portable_path.endswith(ext) for ext in self.config.skip_extensions):
            return True
        # Force-scan allowlist: browser caches/profiles are scanned even though a broader
        # CATEGORY skip (e.g. "/library/caches/") would exclude them. Filename/extension
        # skips above still apply (no point scanning a .iso).
        #
        # Two subtleties, both found in review:
        #  - Match against portable_path + "/" so DIRECTORY paths match too. This function
        #    is called on os.walk's `root` (a directory, normpath-stripped of its trailing
        #    separator) before any file in it is considered; without the appended slash,
        #    "/library/caches/firefox" fails to match the "/library/caches/firefox/"
        #    fragment while still matching the broad "/library/caches/" skip - so the whole
        #    directory was pruned and no file inside ever reached this allowlist.
        #  - It must NOT override BOUNDARY skips (mounted volumes, network shares). Those
        #    exist to keep the scanner on this host, not to reduce noise; a Time Machine
        #    disk under /Volumes/ holds a browser cache per backup snapshot.
        _probe = portable_path + "/"
        if not any(b in _probe for b in getattr(self.config, "force_scan_never_under", ())):
            if any(fragment in _probe for fragment in getattr(self.config, "force_scan_fragments", ())):
                return False
        # Matched as a bounded "/fragment/" substring AND at the tail. os.walk yields a
        # directory root with no trailing separator, so the directory that IS the excluded
        # component (".../node_modules") closed no bounded form and matched nothing, while
        # every file inside it matched. Caught only by re-verifying on real Windows: the
        # Darwin branch masked it locally through its own relative-entry list, so an
        # operator scanning ...\node_modules got 0 files and no exclusion warning on the
        # one platform the fleet actually runs.
        if any(fragment in portable_path or portable_path.endswith(fragment.rstrip("/"))
               for fragment in self.config.skip_path_fragments):
            return True

        if platform.system() == "Windows":
            drive = os.path.splitdrive(normalized_path)[0].rstrip(":")
            if drive in self.config.win_skip_drive:
                return True

            for skip_folder in self.config.win_skip_folder:
                # Match whole path COMPONENTS, not a raw string prefix. A bare startswith()
                # also swallowed every sibling sharing the name: "c:\yara_scanner" matched
                # "c:\yara_scanner_backup\evil.dll", so any directory whose name merely began
                # with a skip entry's was permanently unscannable - a blind spot anyone able
                # to create such a directory could hide in.
                if normalized_path == skip_folder or normalized_path.startswith(skip_folder + "\\"):
                    return True
            return False

        elif platform.system() == "Linux":
            # Filesystems on Linux are typically case-sensitive, so this stays on
            # normalized_path (case-preserved), unlike the Darwin branch below.
            for skip_dir in self.config.lin_skip_directory:
                # skip_dir always carries a trailing "/" (see construction above). A plain
                # startswith() never matches the BARE root os.walk yields for a directory
                # itself (no trailing separator), only its contents - so the root of the
                # scanner's own directory, e.g., was walked and enumerated even though
                # everything inside it was correctly skipped.
                if normalized_path == skip_dir.rstrip("/") or normalized_path.startswith(skip_dir):
                    return True
            return False

        elif platform.system() == "Darwin":
            # APFS is case-insensitive by default, so both sides must be case-folded here -
            # portable_path already is (see its construction above); mac_skip_directory
            # entries are lowercased at construction to match.
            #
            # Entries come in three shapes, and each needs different match semantics:
            #   - starts with "/"    -> an ANCHOR: a real top-level path, meant to match
            #     only there and beneath it (e.g. "/System/" must not match a user's own
            #     "~/System/" directory - that would over-broaden a system-path skip into
            #     matching anything sharing the name anywhere).
            #   - contains ".app/"   -> a BUNDLE SUFFIX: e.g. ".app/Contents/Frameworks/"
            #     is meant to match "Slack.app/Contents/Frameworks/" for ANY app name, so
            #     the character immediately before ".app" is always that name's last letter,
            #     never a path separator - unlike every other fragment below, this one is
            #     deliberately checked WITHOUT requiring a leading "/".
            #   - anything else, no leading "/" -> a FRAGMENT: meant to match this component
            #     wherever it occurs (e.g. "node_modules/" under any project, at any depth) -
            #     the same "anywhere in the path" semantics skip_path_fragments already uses.
            #     A bare startswith() can never satisfy this: a relative string is never a
            #     prefix of an absolute path, so 32 of these 58 entries matched nothing.
            #     Also checked at the tail via endswith (minus the entry's own trailing "/"):
            #     when the fragment's own directory is itself the os.walk root, the path has
            #     no trailing separator to complete the bounded "/entry/" substring, exactly
            #     the same bare-root gap already fixed for anchors above.
            for skip_dir in self.config.mac_skip_directory:
                if skip_dir.startswith("/"):
                    if portable_path == skip_dir.rstrip("/") or portable_path.startswith(skip_dir):
                        return True
                elif ".app/" in skip_dir:
                    if skip_dir in portable_path:
                        return True
                elif (("/" + skip_dir) in portable_path
                      or portable_path.endswith("/" + skip_dir.rstrip("/"))):
                    return True

            filename = os.path.basename(portable_path)
            if filename.startswith('._'):
                return True
            if filename == '.ds_store':
                return True

            return False

        else:
            return False

    def _write_alerts(self, matches, file_path, file_sha256=None, file_creation_time=None):
        """Write alerts for YARA matches."""
        file_detections = []

        for m in matches:
            rule, tags, meta, strings = _iter_hit_fields(m)
            condition_only_detail = None
            if not strings:
                condition_only_detail = _summarize_condition_only_match(
                    rule,
                    meta=meta,
                    tags=tags,
                    rule_source=self.rule_source_map.get(str(rule).lower(), "")
                )

            with self.lock_counts:
                self.detection_counts[rule] += 1
                self.total_detections += 1

            detection_data = {
                'rule_name': rule,
                'file_path': file_path,
                'match_count': len(strings),
                'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                'file_sha256': file_sha256,
                'file_creation_time': file_creation_time
            }
            file_detections.append(detection_data)

            if UPLOAD_RESULTS:
                converted = [(sid, off, data) for (off, sid, data) in strings]
                self.results_uploader.add_match(
                    file_path,
                    rule,
                    converted,
                    file_sha256=file_sha256,
                    file_creation_time=file_creation_time,
                    fallback_detail=condition_only_detail
                )

            alert_path = os.path.join(self.config.alert_dir, f"{rule}.txt")
            with self.lock_alert:
                try:
                    with open(alert_path, "a", encoding="utf-8") as f:
                        f.write(f"\nYARA rule '{rule}' matched file: {file_path}\n")
                        if file_sha256:
                            f.write(f"File SHA256: {file_sha256}\n")
                        if file_creation_time:
                            f.write(f"File Creation Time: {file_creation_time}\n")
                        f.write("=" * 80 + "\n")
                        if strings:
                            # Census first, and deliberately UNCAPPED: which string in the
                            # rule fired and how many times is the detail an analyst works
                            # from, and it costs one line no matter how many offsets there
                            # are. The offsets below are sampled precisely so this can be
                            # complete.
                            id_counts = {}
                            for (_o, _sid, _d) in strings:
                                key = "$?" if _sid is None else str(_sid)
                                id_counts[key] = id_counts.get(key, 0) + 1
                            f.write(f"Total string hits: {len(strings)}\n")
                            f.write("Hits per string ID: " + ", ".join(
                                f"{k}={v}" for k, v in sorted(id_counts.items())) + "\n")
                            f.write("=" * 80 + "\n")

                            cap = MAX_ALERT_OFFSETS_PER_FINDING
                            shown = strings if cap <= 0 else strings[:cap]
                            f.write(
                                f"Matched Strings (showing {len(shown)} of {len(strings)}):\n")
                            f.write("-" * 40 + "\n")
                            for (off, sid, data) in shown:
                                string_repr = _render_match_data(data)
                                f.write(f"String ID: {sid}\n")
                                f.write(f"Offset: {off}\n")
                                f.write(f"Data: {string_repr}\n")
                                f.write("-" * 40 + "\n")
                            if len(shown) < len(strings):
                                f.write(
                                    f"{len(strings) - len(shown)} further offset(s) omitted "
                                    f"(YARA_MAX_ALERT_OFFSETS={cap}). Counts above are complete; "
                                    f"re-run `yara -s` against this file for every offset.\n")
                                f.write("-" * 40 + "\n")
                        elif condition_only_detail:
                            f.write("Condition Match Details:\n")
                            f.write("-" * 40 + "\n")
                            f.write(condition_only_detail + "\n")
                            f.write("-" * 40 + "\n")
                        f.flush()
                except (IOError, OSError) as e:
                    if hasattr(self, 'log_manager'):
                        self.log_manager.log_error(f"Failed to write alert file: {e}")

        # This method no longer emits its own alert event. It used to send
        # "YARA detection event: N rules triggered in <file>" here, while scan_file sent
        # "YARA matches found in <file>" for the SAME file moments later - two rows per
        # matched file carrying overlapping fields (path, sha256, creation time, rule
        # list). Measured on a live storm scan, alerts were 47,460 of 72,484 total rows
        # (65%) at 2.07 events per finding, most of it that duplication. The detail is
        # returned to the caller instead, which emits ONE merged alert.
        return {
            'total_string_matches': sum(len(_iter_hit_fields(m)[3]) for m in matches),
            'detections': file_detections,
            'detection_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def _debug_rule_analysis(self, yara_rule_string):
        """Debug analysis of YARA rules file structure."""
        lines = yara_rule_string.splitlines()
        statements = _get_yara_top_level_statements(yara_rule_string)
        
        logging.info("=== YARA FILE ANALYSIS ===")
        logging.info(f"Total lines: {len(lines)}")
        
        rule_declarations = []
        for statement in statements:
            if statement["type"] != "rule":
                continue
            line_num = yara_rule_string.count("\n", 0, statement["keyword_start"]) + 1
            rule_name = statement["name"] or "unnamed"
            rule_declarations.append((line_num, rule_name))
        
        logging.info(f"Found {len(rule_declarations)} rule declarations")
        
        sample_start = min(5, len(rule_declarations))
        sample_end = min(5, len(rule_declarations))
        
        logging.info("First few rules:")
        for line_num, rule_name in rule_declarations[:sample_start]:
            logging.info(f"  Line {line_num}: rule {rule_name}")
        
        if len(rule_declarations) > 10:
            logging.info("  ...")
            logging.info("Last few rules:")
            for line_num, rule_name in rule_declarations[-sample_end:]:
                logging.info(f"  Line {line_num}: rule {rule_name}")
        
        import_count = len([statement for statement in statements if statement["type"] == "import"])
        logging.info(f"Import statements: {import_count}")
        
        total_open_braces = sum(line.count('{') for line in lines)
        total_close_braces = sum(line.count('}') for line in lines)
        logging.info(f"Total braces: {total_open_braces} opening, {total_close_braces} closing")
        
        if total_open_braces != total_close_braces:
            logging.warning("BRACE MISMATCH DETECTED!")
        
        logging.info("=== END ANALYSIS ===")

    def _get_scan_targets(self):
        """Get scan targets from configuration."""
        if hasattr(self.config, 'scan_targets') and self.config.scan_targets:
            logging.info(f"Using configured scan targets: {self.config.scan_targets}")
            return self.config.scan_targets

        if platform.system() == "Windows":
            targets = self.config._default_discover_targets()
            logging.info(f"Using default Windows targets: {targets}")
            return targets
        
        logging.info("Using default Unix target: ['/']")
        return ["/"]
    
    def _log_progress(self):
        """Log comprehensive progress."""
        with self.lock_counts:
            current_time = time.time()
            elapsed = current_time - self.scan_start_time
            scan_rate = self.files_scanned / elapsed if elapsed > 0 else 0
            
            try:
                # Reuse ONE long-lived, primed handle: psutil's first cpu_percent() call on
                # a given Process object always returns 0.0, so building a fresh
                # psutil.Process() each tick reported 0.0% CPU forever. (Same reasoning as
                # the XDR edition's _governor_proc priming.) Latent before the progress
                # heartbeat existed - this path used to almost never run - but it now fires
                # every log_interval for the whole scan, so the zeros would be the norm.
                process = getattr(self, "_progress_proc", None)
                if process is None:
                    process = psutil.Process()
                    process.cpu_percent(interval=None)   # prime; discard the 0.0
                    self._progress_proc = process
                cpu_percent = process.cpu_percent()
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024

                # io_counters() does not exist on macOS (psutil raises AttributeError).
                # Unguarded it aborted this whole block, zeroing memory/network too - which
                # do work there - and logged an error every tick.
                disk_io_mb = 0
                try:
                    io_counters = process.io_counters()
                    disk_io_mb = (io_counters.read_bytes + io_counters.write_bytes) / 1024 / 1024
                except (AttributeError, NotImplementedError, psutil.AccessDenied):
                    pass

                net_counters = psutil.net_io_counters()
                network_mb = (net_counters.bytes_sent + net_counters.bytes_recv) / 1024 / 1024

                self.log_manager.log_system_resources(cpu_percent, memory_mb, disk_io_mb, network_mb)
                
            except ImportError:
                cpu_percent = memory_mb = disk_io_mb = network_mb = 0
            except Exception as e:
                self.log_manager.log_error(f"Error collecting system metrics: {e}")
                cpu_percent = memory_mb = disk_io_mb = network_mb = 0
            
            active_workers = sum(1 for t in self.scan_threads if t.is_alive())
            queue_size = self.scan_queue.qsize()
            
            self.stats_manager.update_scanner_stats(
                self.files_scanned, self.total_detections, queue_size, active_workers
            )
            
            total_files_estimate = self.files_scanned + self.files_skipped + (queue_size * 2)
            self.stats_manager.calculate_time_estimates(
                self.files_scanned, total_files_estimate, self.scan_start_time
            )
            
            estimates = self.stats_manager.scan_estimates
            eta_seconds = estimates.get('eta_seconds')
            current_rate = estimates.get('current_rate', scan_rate)
            
            additional_metrics = {
                'cpu_percent': cpu_percent,
                'memory_mb': memory_mb,
                'disk_io_mb': disk_io_mb,
                'network_mb': network_mb,
                'active_workers': active_workers,
                'elapsed_seconds': elapsed,
                'eta_seconds': eta_seconds,
                'junction_skips': self.junction_skip_count,
                'unique_real_paths': len(self.scanned_real_paths)
            }

            self.log_manager.log_scan_progress(
                self.files_scanned, self.files_skipped, self.total_detections,
                queue_size, scan_rate, additional_metrics
            )
            
            if eta_seconds:
                completion_time = datetime.datetime.now() + datetime.timedelta(seconds=eta_seconds)
                self.log_manager.log_time_estimates(
                    eta_seconds, completion_time.isoformat(), current_rate,
                    total_files_estimate - self.files_scanned
                )
            
    def _log_final_results(self, total_time):
        """Log comprehensive final results."""
        final_metrics = {
            'total_time_seconds': total_time,
            'files_scanned': self.files_scanned,
            'files_skipped': self.files_skipped,
            'total_detections': self.total_detections,
            'average_scan_rate': self.files_scanned / total_time if total_time > 0 else 0,
            'detection_rate': (self.total_detections / self.files_scanned * 100) if self.files_scanned > 0 else 0,
            'skip_rate': (self.files_skipped / (self.files_scanned + self.files_skipped) * 100) if (self.files_scanned + self.files_skipped) > 0 else 0,
            'junction_skips': self.junction_skip_count,
            'unique_paths_scanned': len(self.scanned_real_paths),
            'path_deduplication_ratio': (self.junction_skip_count / max(self.files_scanned + self.files_skipped, 1)) * 100
        }
        
        status_label = "SCAN FAILED" if self.scan_failed else "SCAN COMPLETED"
        final_message = (
            f"{status_label} | Time: {datetime.timedelta(seconds=int(total_time))} | "
            f"Files: {self.files_scanned} scanned, {self.files_skipped} skipped | "
            f"Detections: {self.total_detections} | "
            f"Rate: {final_metrics['average_scan_rate']:.2f} files/sec"
        )
        if self.scan_failed:
            self.log_manager.log_error(final_message, {
                **final_metrics,
                'failure_reasons': list(self.failure_reasons),
            })
        else:
            self.log_manager.log_statistics(final_message, final_metrics)
        
        if self.total_detections > 0:
            sorted_detections = sorted(self.detection_counts.items(), key=lambda x: x[1], reverse=True)
            top_detections = dict(sorted_detections[:10])
            
            self.log_manager.log_alert(
                f"Top detection rules: {', '.join([f'{rule}({count})' for rule, count in list(top_detections.items())[:5]])}",
                {
                    'total_detections': self.total_detections,
                    'unique_rules_triggered': len(self.detection_counts),
                    'top_10_detections': top_detections
                }
            )

        if self.files_skipped > 0:
            skip_summary = dict(sorted(self.skip_reasons.items(), key=lambda x: x[1], reverse=True))
            self.log_manager.log_statistics(
                f"Skip reasons: {', '.join([f'{reason}({count})' for reason, count in list(skip_summary.items())[:5]])}",
                {'total_skipped': self.files_skipped, 'skip_breakdown': skip_summary}
            )
        
        worker_summary = {}
        for worker_id in self.worker_processing_times:
            if self.worker_processing_times[worker_id]:
                avg_time = sum(self.worker_processing_times[worker_id]) / len(self.worker_processing_times[worker_id])
                worker_summary[worker_id] = {
                    'avg_processing_time_ms': avg_time * 1000,
                    'files_processed': len(self.worker_processing_times[worker_id])
                }
        
        self.log_manager.log_performance(
            f"Worker performance summary: {len(worker_summary)} workers processed files",
            {'worker_details': worker_summary}
        )
                
    def _request_cancel(self, source, log=True):
        """Cooperatively request cancellation. Idempotent (first source wins) and safe from
        any thread: clearing scan_active is what unwinds the producer walk and the workers."""
        with self._cancel_lock:
            if self.cancel_requested:
                return
            self.cancel_requested = True
            self.cancel_source = source
            self.scan_active = False
        if log:
            try:
                self.log_manager.log_system(f"Cancellation requested (source={source})")
            except Exception:
                pass

    def _start_cancellation_watcher(self):
        """Remove a genuinely stale cancel flag, write the running marker, start polling.

        "Stale" = written before this process even started (mtime < process start, minus a
        small tolerance for coarse filesystem mtime resolution). A cancel delivered DURING
        the pre-scan rule-compilation phase has a NEWER mtime and is deliberately preserved,
        so the watcher honours it as soon as it starts - the naive "delete any pre-existing
        flag at startup" version silently loses a cancel issued while a large ruleset is
        still compiling, which is a real window.
        """
        try:
            if os.path.exists(self.cancel_flag_path):
                mtime = os.path.getmtime(self.cancel_flag_path)
                if mtime < (self._process_started_at - CANCEL_STALE_TOLERANCE_SECS):
                    os.remove(self.cancel_flag_path)
                    self.log_manager.log_system("Removed stale cancel flag from a previous run")
        except Exception as e:
            self.log_manager.log_system(f"Could not evaluate pre-existing cancel flag: {e}")

        self._write_running_marker("running")
        self.cancel_watcher_thread = threading.Thread(
            target=self._cancellation_watcher, name="CancelWatcher", daemon=True
        )
        self.cancel_watcher_thread.start()

    def _cancellation_watcher(self):
        """Poll for an operator cancel flag written by a `mode=cancel` invocation."""
        while self.scan_active and not self.cancel_requested:
            try:
                if os.path.exists(self.cancel_flag_path):
                    source = "action_center"
                    try:
                        with open(self.cancel_flag_path, "r", encoding="utf-8") as f:
                            source = (json.load(f) or {}).get("source", source)
                    except Exception:
                        pass
                    self._request_cancel(source)
                    break
                # Inside the try: an exception here (e.g. a bad poll interval) would kill
                # this thread outright, and nothing joins or health-checks it - cancellation
                # would be silently dead for the whole scan while running.json kept
                # advertising a live, cancellable scan.
                time.sleep(CANCEL_POLL_SECS)
            except Exception as e:
                self.log_manager.log_error(f"Cancel watcher error: {e}")
                time.sleep(1.0)

    def _write_running_marker(self, status):
        """Refresh the liveness marker that `mode=cancel` reports against.

        Written atomically (temp + os.replace) so a cross-process cancel reader never sees
        a half-written or empty file.
        """
        try:
            tmp = self.running_marker_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_id": self.config.scan_id,
                    "run_id": getattr(self.config, "run_id", ""),
                    "pid": os.getpid(),
                    "hostname": self.config.hostname,
                    "started_at": self.scan_start_time,
                    "updated_at": time.time(),
                    "status": status,
                    "files_scanned": self.files_scanned,
                    "detections": self.total_detections,
                }, f)
            os.replace(tmp, self.running_marker_path)
            self._last_marker_refresh = time.time()
        except Exception:
            pass

    def _maybe_refresh_running_marker(self):
        """Refresh running.json on a cadence so `cancel` can tell a live scan from a dead
        one. Cheap enough to call from the producer loop; rate-limited here, not by callers."""
        if (time.time() - self._last_marker_refresh) >= RUNNING_MARKER_REFRESH_SECS:
            self._write_running_marker("running")

    def _remove_running_marker(self):
        try:
            if os.path.exists(self.running_marker_path):
                os.remove(self.running_marker_path)
        except Exception:
            pass

    def _clear_cancel_flag(self):
        """Consume the flag once acted on, so it can't cancel the NEXT scan too."""
        try:
            if os.path.exists(self.cancel_flag_path):
                os.remove(self.cancel_flag_path)
        except Exception:
            pass

    def _walk_cancellable(self, target):
        """os.walk replacement whose cancellation latency is bounded by ONE scandir call.

        os.walk yields only after its internal recursion produces the next directory, so
        `scan_active` can go unobserved for an unbounded interval - measured in the XDR
        edition on C:\\ : workers stopped 4.45s after a cancel but the process took a further
        50s to exit because the walk was still inside the generator, which also left
        running.json stale so `cancel` reported "scanner running: no" during a live scan.

        Driving the traversal with an explicit stack puts the check under our control: it
        runs before every directory and between entries, so a cancel is honoured within a
        single scandir.

        Contract matches os.walk(topdown=True): yields (dirpath, dirnames, filenames), and
        the caller may prune `dirnames` in place to skip subtrees - the stack is extended
        after the yield, so pruning is respected. Symlinked directories are listed in
        dirnames but not recursed into, matching followlinks=False.
        """
        stack = [target]
        while stack:
            if not self.scan_active:
                return
            current = stack.pop()
            dirnames, filenames, symlinked = [], [], set()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if not self.scan_active:
                            return
                        try:
                            if entry.is_dir():
                                dirnames.append(entry.name)
                                if entry.is_symlink():
                                    symlinked.add(entry.name)
                            else:
                                filenames.append(entry.name)
                        except OSError:
                            # Unreadable entry: classify as a file so the normal per-file
                            # error path reports it rather than silently dropping it.
                            filenames.append(entry.name)
            except (PermissionError, FileNotFoundError, NotADirectoryError):
                continue
            except OSError:
                continue

            yield current, dirnames, filenames

            # Extended AFTER the yield so caller-side pruning of dirnames is respected.
            for name in reversed(dirnames):
                if name in symlinked:
                    continue
                stack.append(os.path.join(current, name))

    def _progress_heartbeat(self):
        """Periodic _log_progress() call spanning the WHOLE scan (discovery + the time
        workers spend draining scan_queue afterward), not just file discovery. The old
        approach checked this only inline in the discovery os.walk loop, which almost
        never runs long enough on its own to cross log_interval - file enumeration is
        fast; matching file content in the worker threads is what actually takes minutes,
        and that happens after discovery ends. Confirmed live: zero "Scan Progress" events
        were ever recorded under the old approach, on any host.
        """
        while not self._progress_heartbeat_stop.wait(self.config.log_interval):
            if not self.scan_active:
                break
            try:
                self._log_progress()
            except Exception as e:
                self.log_manager.log_error(f"Progress heartbeat error: {e}")
            # Refresh the liveness marker from this TIMED thread rather than relying only on
            # the per-directory call in the discovery loop. That loop's inner
            # _enqueue_scan_path blocks while the scan queue is saturated, so one huge
            # directory can hold it well past RUNNING_MARKER_STALE_SECS - during which
            # `cancel` would report "scanner running: no" about a scan that is very much
            # alive, pushing the operator toward the console hard-kill this feature exists
            # to replace. Self-rate-limited, so calling it every tick is cheap.
            try:
                self._maybe_refresh_running_marker()
            except Exception:
                pass

    def _perform_enhanced_cleanup(self, start_time, total_files_found, files_per_target):
        """Enhanced cleanup with aggressive timeouts."""
        self.log_manager.log_system("=== ENHANCED CLEANUP AND FINALIZATION ===")
        self.status_uploader.set_status("finishing")

        cleanup_start = time.time()
       

        # Resource/stats monitoring is stopped AFTER the worker-thread join below, not
        # here. File discovery finishing (which is where control reaches this point) is
        # not the same as the workers finishing the matching work still sitting in
        # scan_queue - on a large scan those can be minutes apart, and stopping the
        # monitor here was cutting resource telemetry off for most of the real scan
        # duration.
        self.log_manager.log_system("Initiating worker thread cleanup")
        
        for _ in range(self.config.max_workers):
            try:
                self.scan_queue.put(None, timeout=1.0)
            except Exception:
                pass

        self.log_manager.log_system("Waiting for workers to terminate (max 30 seconds)")
        
        worker_join_start = time.time()
        successful_joins = 0
        failed_joins = 0
        remaining_threads = []

        for t in self.scan_threads:
            try:
                t.join(timeout=5)
                if t.is_alive():
                    remaining_threads.append(t.name)
                    self.log_manager.log_error(f"Worker thread {t.name} did not finish - continuing anyway")
                    failed_joins += 1
                else:
                    successful_joins += 1
            except Exception as e:
                self.log_manager.log_error(f"Error joining thread {t.name}: {e}")
                failed_joins += 1
        if remaining_threads:
            self.log_manager.log_error(f"Threads did not terminate: {remaining_threads}")
 
        worker_join_time = time.time() - worker_join_start
        self.log_manager.log_performance(
            f"Worker cleanup: {successful_joins} stopped, {failed_joins} timed out in {worker_join_time:.1f}s"
        )

        # Stopped here, AFTER the join above, for the same reason as resource/stats
        # monitoring below - the heartbeat needs to keep firing for as long as workers
        # are actually still draining scan_queue, not just until file discovery ends.
        if getattr(self, '_progress_heartbeat_stop', None) is not None:
            self._progress_heartbeat_stop.set()
            if getattr(self, '_progress_heartbeat_thread', None) is not None:
                self._progress_heartbeat_thread.join(timeout=2)

        # Consume the cancel flag (so it cannot also cancel the NEXT scan) and drop the
        # liveness marker (so `mode=cancel` correctly reports no scan running).
        if getattr(self, "cancel_requested", False):
            self._clear_cancel_flag()
        self._remove_running_marker()

        try:
            if getattr(self, 'resource_monitor', None) is not None:
                self.resource_monitor.stop_monitoring()
            self.stats_manager.stop_monitoring()
        except Exception as e:
            self.log_manager.log_error(f"Error stopping monitoring: {e}")

        self.scan_active = False
        cleanup_total_time = time.time() - cleanup_start
        
        try:
            if hasattr(self, "results_uploader") and self.results_uploader:
                self.results_uploader.stop(wait=True)
            # NOTE: webhook_uploader is intentionally NOT stopped here. main()
            # still queues comprehensive_final_report and scan_completion_summary
            # via this uploader after scan_system() returns. Stopping it here
            # silently drops those end-of-run summary events. The uploader is
            # stopped in main()'s finally block, after all queuing is done.
        except Exception as e:
            self.log_manager.log_error(f"Error stopping uploaders: {e}")
        
        self.log_manager.log_system(f"Enhanced cleanup completed in {cleanup_total_time:.1f} seconds")

    def scan_system(self):
        """Main system scan orchestration."""
        start_time = time.time()
        
        self.resource_monitor = None
        if self.config.enable_resource_monitoring:
            self.resource_monitor = SystemResourceMonitor(self.config, self.log_manager, self.webhook_uploader)
        
        self.log_manager.log_system("=== ENHANCED SYSTEM SCAN INITIATED ===")
        self.log_manager.log_system(
            "All monitoring systems activated",
            {
                'statistics_monitoring': True,
                'performance_monitoring': self.config.enable_performance_monitoring,
                'resource_monitoring': self.config.enable_resource_monitoring,
                'webhook_uploading': UPLOAD_RESULTS,
                'worker_threads': self.config.max_workers,
                'light_throttling': self.config.light_throttle_enabled,
            }
        )
        
        self.status_uploader.set_status("initializing")
        
        targets = self._get_scan_targets()
        self.scan_targets = targets
        
        scan_config_data = {
            'scan_id': f"{self.config.hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'os_info': self.config.os_info,
            'targets': targets,
            'target_count': len(targets),
            'max_workers': self.config.max_workers,
            'max_file_size_mb': self.config.max_file_mb,
            'yara_rules_count': self.config.error_logger.valid_rules_count,
            'failed_rules_count': self.config.error_logger.failed_rules_count
        }
        
        self.log_manager.log_statistics("Scan configuration established", scan_config_data)
        self.webhook_uploader.upload_statistics_summary({
            'phase': 'scan_configuration',
            'data': scan_config_data
        })
        
        self.status_uploader.set_status("starting_workers")
        worker_start_time = time.time()
        
        for i in range(self.config.max_workers):
            t = threading.Thread(target=self._worker, name=f"ScanWorker-{i+1}", daemon=True)
            t.start()
            self.scan_threads.append(t)
        
        worker_startup_time = time.time() - worker_start_time
        self.log_manager.log_performance_critical(
            f"Worker thread startup completed in {worker_startup_time:.2f} seconds",
            {'worker_startup_time_seconds': worker_startup_time, 'workers_started': len(self.scan_threads)}
        )

        self._progress_heartbeat_stop = threading.Event()
        self._progress_heartbeat_thread = threading.Thread(
            target=self._progress_heartbeat, name="ProgressHeartbeat", daemon=True
        )
        self._progress_heartbeat_thread.start()

        self._start_cancellation_watcher()

        total_files_found = 0
        files_per_target = {}

        try:
            self.status_uploader.set_status("scanning")
            self.log_manager.log_system("=== ACTIVE SCANNING PHASE STARTED ===")
            
            for target_idx, target in enumerate(targets):
                if not self.scan_active:
                    self.log_manager.log_system("Scan terminated by external signal")
                    break
                
                target_start_time = time.time()
                target_files_found = 0
                
                try:
                    self.log_manager.log_system(
                        f"Scanning target {target_idx + 1}/{len(targets)}: {target}",
                        {'target_index': target_idx + 1, 'target_path': target}
                    )

                    # The operator asked for this path explicitly, but it matches the skip
                    # list, so the walk below drops every directory in it and reports a
                    # clean zero. Record it so the result line can say so - silently
                    # returning 0 reads as "nothing here", not "policy excluded this".
                    if self._is_special_file(target):
                        self.excluded_targets.append(target)
                        self.log_manager.log_error(
                            f"Requested scan target is excluded by the skip list, so nothing "
                            f"under it will be scanned: {target}",
                            {'target_path': target, 'reason': 'skip_list'}
                        )
                    
                    for root, dirs, files in self._walk_cancellable(target):
                        if not self.scan_active:
                            break

                        self._maybe_refresh_running_marker()

                        if self._is_special_file(root):
                            # Count what this skip actually excluded. A bare `continue`
                            # touched no counter, so an entire skipped subtree vanished
                            # from the books: files_scanned + files_skipped could not be
                            # reconciled against what is on disk, and skip_rate read 0%.
                            # Subdirectories are not pruned, so each one arrives here as
                            # its own root and contributes its own files - the whole
                            # subtree is counted exactly once.
                            if files:
                                with self.lock_counts:
                                    self.files_skipped += len(files)
                                    self.skip_reasons["Skipped directory"] += len(files)
                            continue
                        
                        dirs[:] = [d for d in dirs if not _should_skip_junction(os.path.join(root, d))]
                        
                        for name in files:
                            if not self.scan_active:
                                break
                                
                            path = os.path.join(root, name)
                            
                            if _should_skip_junction(path):
                                with self.lock_counts:
                                    self.files_skipped += 1
                                    self.skip_reasons["Junction/symlink skip"] += 1
                                    self.junction_skip_count += 1
                                continue
                                
                            total_files_found += 1
                            target_files_found += 1
                            
                            if self._is_special_file(path):
                                with self.lock_counts:
                                    self.files_skipped += 1
                                    self.skip_reasons["Special system file"] += 1
                                continue
                            
                            if not self._enqueue_scan_path(path):
                                break

                    target_scan_time = time.time() - target_start_time
                    files_per_target[target] = target_files_found
                    
                    self.log_manager.log_statistics_critical(
                        f"Target scan completed: {target}",
                        {
                            'target': target,
                            'files_found': target_files_found,
                            'scan_time_seconds': target_scan_time,
                            'files_per_second': target_files_found / target_scan_time if target_scan_time > 0 else 0
                        }
                    )
                    
                except Exception as e:
                    self.log_manager.log_error(f"Error scanning target {target}: {e}")
                    continue

        except Exception as e:
            error_msg = f"Critical error during scan execution: {e}"
            self.log_manager.log_error(error_msg)
            self._mark_scan_failed(error_msg)
            self.status_uploader.set_status("error")
        
        finally:
            scan_total_time = time.time() - start_time
            self._perform_enhanced_cleanup(start_time, total_files_found, files_per_target)
            self._log_final_results(scan_total_time)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def setup_logging(config):
    """Quiet the root logger.

    Categorized logging is handled by LogManager; root-logger output is
    suppressed below WARNING to avoid noisy stdout during scans. WARNING and
    ERROR records still surface to stderr via Python's default handler so
    customers running interactively can see fatal issues.
    """
    try:
        for handler in logging.root.handlers[:]:
            handler.close()
            logging.root.removeHandler(handler)
        logging.root.setLevel(logging.WARNING)
    except Exception as e:
        print(f"Error quieting root logger: {e}")


def upload_final_comprehensive_report(scanner, total_scan_time):
    """Upload comprehensive final report."""
    try:
        final_report_data = {
            'scan_metadata': {
                'hostname': scanner.config.hostname,
                'os_info': scanner.config.os_info,
                'ip_addresses': scanner.config.ip_addresses,
                'scan_duration_seconds': total_scan_time,
                'scan_start_time': datetime.datetime.fromtimestamp(scanner.scan_start_time, tz=datetime.timezone.utc).isoformat(),
                'scan_end_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'targets_scanned': scanner.scan_targets
            },
            
            'file_processing': {
                'total_files_scanned': scanner.files_scanned,
                'total_files_skipped': scanner.files_skipped,
                'total_files_processed': scanner.files_scanned + scanner.files_skipped,
                'skip_breakdown': dict(scanner.skip_reasons),
                'processing_rate': scanner.files_scanned / total_scan_time if total_scan_time > 0 else 0
            },
            
            'detection_results': {
                'total_detections': scanner.total_detections,
                'unique_rules_triggered': len(scanner.detection_counts),
                'detection_breakdown': dict(scanner.detection_counts),
                'top_10_rules': dict(sorted(scanner.detection_counts.items(), 
                                          key=lambda x: x[1], reverse=True)[:10]),
                'detection_rate_percent': (scanner.total_detections / max(scanner.files_scanned, 1)) * 100
            },
            
            'rule_compilation': {
                'valid_rules_loaded': scanner.config.error_logger.valid_rules_count,
                'failed_rules_skipped': scanner.config.error_logger.failed_rules_count,
                'total_rules_processed': scanner.config.error_logger.valid_rules_count + scanner.config.error_logger.failed_rules_count,
                'compilation_success_rate': (scanner.config.error_logger.valid_rules_count / 
                                           max(scanner.config.error_logger.valid_rules_count + scanner.config.error_logger.failed_rules_count, 1)) * 100
            },
            
            'system_info': {
                'platform': platform.platform(),
                'python_version': sys.version,
                'yara_version': getattr(yara, '__version__', 'Unknown'),
                'cpu_count': os.cpu_count(),
                'worker_threads_used': scanner.config.max_workers
            }
        }
        
        if hasattr(scanner, 'stats_manager'):
            performance_data = scanner.stats_manager.get_current_stats_for_upload()
            final_report_data['performance_summary'] = performance_data
                    
        if getattr(scanner, 'resource_monitor', None) is not None:
            resource_summary = scanner.resource_monitor.get_resource_summary()
            final_report_data['resource_summary'] = resource_summary
        
        if hasattr(scanner, 'webhook_uploader'):
            upload_stats = scanner.webhook_uploader.get_upload_statistics()
            final_report_data['upload_summary'] = upload_stats
        
        efficiency_score = 100
        if final_report_data['file_processing']['total_files_processed'] > 0:
            skip_rate = final_report_data['file_processing']['total_files_skipped'] / final_report_data['file_processing']['total_files_processed']
            efficiency_score -= (skip_rate * 20)
        
        if final_report_data['rule_compilation']['total_rules_processed'] > 0:
            rule_failure_rate = final_report_data['rule_compilation']['failed_rules_skipped'] / final_report_data['rule_compilation']['total_rules_processed']
            efficiency_score -= (rule_failure_rate * 30)
        
        final_report_data['efficiency_score'] = max(0, efficiency_score)
        
        if hasattr(scanner, 'webhook_uploader'):
            standard_log = create_standard_log(
                log_type='comprehensive_final_report',
                hostname=scanner.config.hostname,
                os_info=scanner.config.os_info,
                ip_address=scanner.config.ip_addresses[0] if scanner.config.ip_addresses else "Unknown",
                scan_id=scanner.config.scan_id,
                message=f"Comprehensive scan report - Efficiency Score: {efficiency_score:.1f}/100",
                level="INFO",
                data=final_report_data
            )
            scanner.webhook_uploader._queue_standard_upload(standard_log, priority=True)
        
        if hasattr(scanner, 'log_manager'):
            scanner.log_manager.log_statistics(
                f"COMPREHENSIVE SCAN REPORT | Efficiency Score: {efficiency_score:.1f}/100",
                final_report_data
            )
        
        logging.info(f"Comprehensive final report generated - Efficiency Score: {efficiency_score:.1f}/100")
        
    except Exception as e:
        if hasattr(scanner, 'log_manager'):
            scanner.log_manager.log_error(f"Error generating comprehensive final report: {e}")
        logging.error(f"Error uploading final comprehensive report: {e}")


def cancel():
    """Action Center entry point - cancel a running scan on this endpoint (NO inputs).

    Kept as a separate zero-input entry point rather than a `mode` parameter on main():
    Action Center's "Run by entry point" derives a script's input list from the function
    signature, so adding a parameter to main() would change its 3-input contract and make
    every existing run_script call fail parameter validation.
    """
    return _handle_cancel_request()


def main(yarafile=None, scan_folder=None, alert_severity="low"):
    """Main entry point for YARA scanner."""
    config = None
    log_manager = None
    stats_manager = None
    webhook_uploader = None
    exception_logger = None
    
    try:
        config = ScanConfig(
            yarafile,
            scan_folder=scan_folder,
            alert_severity=alert_severity,
        )
        log_manager = LogManager(config)
        _apply_light_process_priority(log_manager)
        exception_logger = config.exception_logger
        stats_manager = StatisticsManager(config, log_manager)
        webhook_uploader = WebhookUploader(config, log_manager)
        cleanup_manager = CleanupManager(config)
        
        cleanup_manager.initial_cleanup()
        log_manager.log_system("Initial cleanup completed")

        # Fail LOUD, fail EARLY on placeholder collector credentials. With the defaults still in
        # place every webhook POST fails (one bounded-retry cycle per matched string), the scan
        # "completes" with nothing ingested, and the failure is only visible in endpoint logs.
        # An explicit abort surfaces the misconfiguration in the Action Center result instead.
        _ep = str(API_ENDPOINT or "").strip()
        _key = str(API_KEY or "").strip()
        _ep_bad = (not _ep) or (_ep == _PLACEHOLDER_API_ENDPOINT) or (not _ep.lower().startswith("http"))
        _key_bad = (not _key) or (_key == _PLACEHOLDER_API_KEY)
        if UPLOAD_RESULTS and (_ep_bad or _key_bad):
            abort_msg = (
                "SCAN ABORTED - XSIAM HTTP Collector credentials are not set. Edit DEFAULT_API_KEY / "
                "DEFAULT_API_ENDPOINT (or disable UPLOAD_RESULTS for a local-only scan) and re-upload "
                "the script. Nothing was scanned."
            )
            log_manager.log_error(abort_msg)
            return abort_msg

        if platform.system() != "Windows":
            import os
            is_root = os.geteuid() == 0
            
            if platform.system() == "Darwin":
                log_manager.log_system(f"Running as: {'root' if is_root else 'non-root user'} on macOS")
                
                if is_root:
                    log_manager.log_system("NOTE: System Integrity Protection (SIP) may restrict access to /System/")
                else:
                    log_manager.log_system("WARNING: Not running as root - some system files may be inaccessible")
                    log_manager.log_system("TIP: Run with 'sudo' for broader system access")
                    log_manager.log_system("TIP: Grant 'Full Disk Access' in System Settings > Privacy & Security")
                    
            else:
                log_manager.log_system(f"Running as: {'root' if is_root else 'non-root user'} on Linux")
                
                if not is_root:
                    log_manager.log_system("WARNING: Not running as root - some system files may be inaccessible")
                    log_manager.log_system("For complete system scan, run with: sudo python3 yara_scanner.py")
            
            if not is_root:
                if platform.system() == "Darwin":
                    system_paths = ['/System', '/Library', '/private/var/db']
                else:
                    system_paths = ['/etc', '/boot', '/var/log', '/root']
                
                _requested_folders = [p.strip().strip('"').strip("'")
                                      for p in str(scan_folder or "").split(",") if p.strip()]
                if any(f.startswith(path) for f in _requested_folders for path in system_paths):
                    log_manager.log_system("ERROR: System path scan requires elevated privileges")
                    if platform.system() == "Darwin":
                        log_manager.log_system("Either run as root (sudo) or grant Full Disk Access")
                    else:
                        log_manager.log_system("Either run as root or choose a different scan path")

                if webhook_uploader:
                    standard_log = create_standard_log(
                        log_type='privilege_status',
                        hostname=config.hostname,
                        os_info=config.os_info,
                        ip_address=config.ip_addresses[0],
                        scan_id=config.scan_id,
                        message="Scanner privilege level detected",
                        level="WARNING" if not is_root else "INFO",
                        data={
                            'platform': 'linux',
                            'running_as_root': is_root,
                            'recommended_action': 'run_as_sudo' if not is_root else 'none'
                        }
                    )
                    webhook_uploader._queue_standard_upload(standard_log)

        if platform.system() != "Windows" and config.enable_fd_monitoring:
            try:
                import subprocess
                try:
                    result = subprocess.run(['bash', '-c', 'ulimit -n'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        current_limit = int(result.stdout.strip())
                        log_manager.log_system(f"Current file descriptor limit: {current_limit}")
                        
                        if current_limit < 8192:
                            log_manager.log_system(f"WARNING: Low file descriptor limit ({current_limit})")
                            log_manager.log_system("Consider running: ulimit -n 65536 before starting scanner")
                            
                            if webhook_uploader:
                                standard_log = create_standard_log(
                                    log_type='resource_limit_warning',
                                    hostname=config.hostname,
                                    os_info=config.os_info,
                                    ip_address=config.ip_addresses[0],
                                    scan_id=config.scan_id,
                                    message="Low file descriptor limit detected",
                                    level="WARNING",
                                    data={
                                        'current_limit': current_limit,
                                        'recommended_limit': 65536,
                                        'impact': 'May affect scanning performance on large directories'
                                    }
                                )
                                webhook_uploader._queue_standard_upload(standard_log)
                                
                    else:
                        log_manager.log_system("Could not determine file descriptor limit")
                        
                except Exception as e:
                    log_manager.log_system(f"Could not check file descriptor limit: {e}")
                    
                try:
                    current_process = psutil.Process()
                    if hasattr(current_process, 'num_fds'):
                        initial_fds = current_process.num_fds()
                        log_manager.log_system(f"Initial file descriptors in use: {initial_fds}")
                        config.initial_fd_count = initial_fds
                        config.monitor_fd_usage = True
                    else:
                        config.monitor_fd_usage = False
                        
                except Exception as e:
                    log_manager.log_system(f"Could not setup FD monitoring: {e}")
                    config.monitor_fd_usage = False
                    
            except Exception as e:
                log_manager.log_system(f"Could not setup file descriptor management: {e}")
        else:
            config.monitor_fd_usage = False
        
        setup_logging(config)
        
        log_manager.log_system("=" * 80)
        log_manager.log_system("ENHANCED YARA SCANNER INITIALIZATION (STANDARDIZED)")
        log_manager.log_system("=" * 80)
        
        init_data = {
            'hostname': config.hostname,
            'os_info': config.os_info,
            'ip_addresses': config.ip_addresses,
            'platform': platform.platform(),
            'python_version': sys.version,
            'yara_version': getattr(yara, '__version__', 'Unknown'),
            'rule_source': "provided parameter" if yarafile else "default configuration",
            'scan_targets': config.scan_targets if hasattr(config, 'scan_targets') else "default system scan",
            'max_workers': config.max_workers,
            'scan_queue_size': config.scan_queue_size,
            'max_file_mb': config.max_file_mb,
            'scanner_profile': 'light',
            'performance_monitoring_enabled': config.enable_performance_monitoring,
            'resource_monitoring_enabled': config.enable_resource_monitoring,
            'upload_enabled': UPLOAD_RESULTS,
            'webhook_key_source': config.webhook_key_source,
            'webhook_endpoint_source': config.webhook_endpoint_source,
            'api_endpoint': API_ENDPOINT,
            'default_alert_severity': config.alert_severity,
            'telemetry_upload_enabled': UPLOAD_NON_MATCH_DATA,
            'logging_format': 'standardized'
        }
        
        log_manager.log_system("YARA Scanner initialization completed", init_data)
        
        if config.scan_folder and config.scan_folder.lower() != "default":
            scope_message = f"SCAN SCOPE: Limited to specified targets: {config.scan_targets}"
        else:
            scope_message = "SCAN SCOPE: Full system scan (light profile throttling enabled)"
        
        log_manager.log_system(scope_message, {'scan_targets': getattr(config, 'scan_targets', 'default')})
        
        top_level_statements = _get_yara_top_level_statements(config.yara_rule)
        rule_count = len([stmt for stmt in top_level_statements if stmt["type"] == "rule"])
        import_count = len([stmt for stmt in top_level_statements if stmt["type"] == "import"])
        
        rules_data = {
            'total_rules_found': rule_count,
            'import_statements': import_count,
            'rule_content_length': len(config.yara_rule)
        }
        
        log_manager.log_system(f"YARA Rules loaded: {rule_count} rules, {import_count} imports", rules_data)
        
        standard_log = create_standard_log(
            log_type='scanner_initialization',
            hostname=config.hostname,
            os_info=config.os_info,
            ip_address=config.ip_addresses[0] if config.ip_addresses else "Unknown",
            scan_id=config.scan_id,
            message="YARA Scanner initialized successfully",
            level="INFO",
            data=init_data
        )
        webhook_uploader._queue_standard_upload(standard_log, priority=True)
        
        scanner = YaraScanner(config, log_manager=log_manager, stats_manager=stats_manager)
        scanner.webhook_uploader = webhook_uploader
        scanner.status_uploader.webhook_uploader = webhook_uploader
        error_logger = config.error_logger
        stats_manager.start_monitoring()
        
        compilation_data = {
            'valid_rules_compiled': error_logger.valid_rules_count,
            'failed_rules_skipped': error_logger.failed_rules_count,
            'compilation_success_rate': (error_logger.valid_rules_count / max(error_logger.valid_rules_count + error_logger.failed_rules_count, 1)) * 100
        }
        
        if error_logger.valid_rules_count > 0:
            log_manager.log_system(f"Scanner initialized with {error_logger.valid_rules_count} valid rules", compilation_data)
            if error_logger.failed_rules_count > 0:
                log_manager.log_error(f"Skipped {error_logger.failed_rules_count} failed rules", compilation_data)
        
        webhook_uploader.upload_statistics_summary({
            'phase': 'initialization',
            'system_info': init_data,
            'compilation_results': compilation_data
        })
        
        scan_start_time = time.time()
        log_manager.log_system("=== STARTING ENHANCED SYSTEM SCAN (STANDARDIZED) ===")
        
        try:
            scanner.scan_system()
        except KeyboardInterrupt:
            log_manager.log_system("Scan interrupted by user (Ctrl+C)")
            scanner.scan_active = False
            scanner.scan_failed = True
            scanner.failure_reasons.append("Scan interrupted by user")
            scanner.status_uploader.set_status("interrupted")
        except Exception as e:
            log_manager.log_error(f"Error during scanning: {e}", {'error_type': type(e).__name__})
            scanner.status_uploader.set_status("error")
            raise

        if scanner.scan_failed:
            failure_data = {
                'failure_count': len(scanner.failure_reasons),
                'failure_reasons': scanner.failure_reasons[:20],
                'files_scanned': scanner.files_scanned,
                'files_skipped': scanner.files_skipped,
                'detections': scanner.total_detections,
            }
            log_manager.log_error("Scan stopped due to fatal failures", failure_data)
            return (
                f"Scan failed: {scanner.files_scanned} files scanned | "
                f"{error_logger.failed_rules_count} rules failed compilation | "
                f"{scanner.total_detections} matches found | "
                f"Fatal failures: {len(scanner.failure_reasons)}"
            )
        
        scan_total_time = time.time() - scan_start_time
        
        final_performance_stats = stats_manager.get_current_stats_for_upload()
        final_upload_stats = webhook_uploader.get_upload_statistics()
        final_log_stats = log_manager.get_upload_statistics()
        
        comprehensive_final_stats = {
            'scan_duration_seconds': scan_total_time,
            'scan_duration_formatted': str(datetime.timedelta(seconds=int(scan_total_time))),
            'files_processed': scanner.files_scanned + scanner.files_skipped,
            'files_scanned': scanner.files_scanned,
            'files_skipped': scanner.files_skipped,
            'total_detections': scanner.total_detections,
            'unique_rules_triggered': len(scanner.detection_counts),
            'performance_metrics': final_performance_stats,
            'webhook_upload_stats': final_upload_stats,
            'log_generation_stats': final_log_stats,
            'error_summary': {
                'compilation_errors': error_logger.failed_rules_count,
                'scan_errors': sum(count for reason, count in scanner.skip_reasons.items()
                                   if 'error' in reason.lower())
            }
        }
        
        # Telemetry must agree with the returned result and the summary JSON. Reporting
        # "completed successfully" for a run the operator cancelled makes the dashboard
        # contradict the Action Center output, and hides that the counts are partial.
        _was_cancelled = getattr(scanner, "cancel_requested", False)
        _elapsed_txt = datetime.timedelta(seconds=int(scan_total_time))
        _completion_msg = (
            f"Scan cancelled by operator after {_elapsed_txt} (partial results)"
            if _was_cancelled else
            f"Scan completed successfully in {_elapsed_txt}"
        )
        comprehensive_final_stats['outcome'] = "cancelled" if _was_cancelled else "completed"
        if _was_cancelled:
            comprehensive_final_stats['cancel_source'] = getattr(scanner, "cancel_source", "")

        standard_log = create_standard_log(
            log_type='scan_completion_summary',
            hostname=config.hostname,
            os_info=config.os_info,
            ip_address=config.ip_addresses[0] if config.ip_addresses else "Unknown",
            scan_id=config.scan_id,
            message=_completion_msg,
            level="INFO",
            data=comprehensive_final_stats
        )
        webhook_uploader._queue_standard_upload(standard_log, priority=True)

        upload_final_comprehensive_report(scanner, scan_total_time)

        log_manager.log_statistics(
            (f"SCAN CANCELLED BY OPERATOR after {_elapsed_txt}" if _was_cancelled
             else f"SCAN COMPLETED SUCCESSFULLY in {_elapsed_txt}"),
            comprehensive_final_stats
        )
        
        try:
            scanner.evidence_collector.collect_evidence()
            log_manager.log_system("Evidence collection completed successfully")
        except Exception as e:
            log_manager.log_error(f"Error collecting evidence: {e}")
        
        try:
            has_critical_errors = (error_logger.has_errors and error_logger.valid_rules_count == 0)
            
            if not has_critical_errors:
                cleanup_manager.schedule_final_cleanup()
                log_manager.log_system("Cleanup task/service scheduled successfully")
            else:
                log_manager.log_system("Cleanup skipped due to critical YARA processing errors")
        except Exception as e:
            log_manager.log_error(f"Error scheduling cleanup: {e}")
        
        try:
            upload_stats = webhook_uploader.get_upload_statistics() if webhook_uploader else {'summary': {'failed_uploads': 0}}
            if upload_stats['summary']['failed_uploads'] > 0:
                sys.stdout.write(f"WARNING: {upload_stats['summary']['failed_uploads']} upload operations failed\n")
                sys.stdout.write("Scan completed successfully but some results may not have been uploaded\n")
                sys.stdout.flush()
        except Exception:
            pass

        if 'scanner' in locals() and hasattr(scanner, 'scan_threads'):
            remaining_threads = [t for t in scanner.scan_threads if t.is_alive()]
            if remaining_threads:
                log_manager.log_system(f"Waiting for {len(remaining_threads)} remaining threads to terminate")
                for t in remaining_threads:
                    t.join(timeout=2)
                    
        log_manager.log_system("=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===")
        
        upload_errors = ""
        try:
            upload_stats = webhook_uploader.get_upload_statistics() if webhook_uploader else {'summary': {'failed_uploads': 0}}
            if upload_stats['summary']['failed_uploads'] > 0:
                upload_errors = f" | Upload errors: {upload_stats['summary']['failed_uploads']}"
        except Exception:
            upload_errors = " | Upload errors: unknown"

        # Surface MATCH-channel loss on the result line itself. upload_errors above only
        # reflects the telemetry uploader, so a scan that found everything and delivered
        # none of its findings still read as a clean success. Both counters are real loss
        # but are named misleadingly differently: 'undelivered' items were never attempted
        # (the drain window expired), 'failed_uploads' were attempted and rejected.
        # Ported from the XDR edition's _delivery_shortfall().
        #
        # The denominator is deliberately ok+failed+undelivered, NOT total_matches:
        # total_matches counts OFFSETS (incremented per matched string instance), while
        # these three count UPLOAD ITEMS - one per (rule, file) finding since the
        # grain-split change. Mixing the two understates loss by the average
        # offsets-per-finding factor, which on a noisy rule is a factor of thousands.
        #
        # Read after _perform_enhanced_cleanup has called results_uploader.stop(wait=True),
        # so these are the settled values; a worker that overran its join could in principle
        # still move them, which would only ever under-report, never invent loss.
        shortfall = ""
        try:
            ru = getattr(scanner, "results_uploader", None)
            s = ru.get_upload_stats() if ru else {}
            ok = int(s.get("successful_uploads", 0) or 0)
            failed = int(s.get("failed_uploads", 0) or 0)
            undelivered = int(s.get("undelivered", 0) or 0)
            lost = failed + undelivered
            if lost > 0:
                queued = ok + lost
                shortfall = (f" | WARNING: {lost} of {queued} finding upload(s) NOT delivered "
                             f"(failed={failed}, undelivered={undelivered}) - "
                             f"local logs hold the complete record")
        except Exception:
            pass

        # A cancelled scan must not report "Scan completed" - it stopped early by request,
        # so its file/match counts are a partial view of the target and reading them as a
        # clean full result is wrong. (Caught in testing: a cancel that truncated a scan at
        # 1,669 of 4,000 files still returned "Scan completed".)
        if getattr(scanner, "cancel_requested", False):
            _verb = f"Scan cancelled (source={getattr(scanner, 'cancel_source', 'unknown')})"
        else:
            _verb = "Scan completed"
        # Skipped rules are NOT failures (the agent's libyara lacks the module they need),
        # but they did not run either - so they must be visible here. Otherwise a pack whose
        # rules were mostly skipped reports "0 rules failed compilation" and reads clean.
        _skipped = getattr(error_logger, "skipped_rules_count", 0) or 0
        _skipped_txt = f" | {_skipped} rules skipped (module unavailable)" if _skipped else ""
        # A target the operator explicitly asked for but the skip list excludes wholesale
        # must be named on the result line. Reporting only "0 files scanned" is
        # indistinguishable from an empty directory, so a scan of e.g. AppData\Local\Temp
        # read as a clean success with zero coverage.
        _excluded = list(getattr(scanner, "excluded_targets", []) or [])
        _excl_txt = ""
        if _excluded:
            _excl_txt = (f" | WARNING: {len(_excluded)} requested target(s) EXCLUDED by the "
                         f"skip list, nothing under them was scanned: "
                         + ", ".join(_excluded[:3])
                         + (" ..." if len(_excluded) > 3 else ""))
        summary = (f"{_verb}: {scanner.files_scanned} files scanned | "
                f"{error_logger.failed_rules_count} rules failed compilation{_skipped_txt} | "
                f"{scanner.total_detections} matches found{upload_errors}{shortfall}{_excl_txt}")
        return summary
        
    except Exception as e:
        error_msg = f"Critical scanner error: {str(e)}"
        
        sys.stderr.write(f"YARA Scanner Critical Error: {error_msg}\n")
        sys.stderr.write(f"Error Type: {type(e).__name__}\n")
        sys.stderr.write(f"Full traceback:\n{traceback.format_exc()}\n")
        sys.stderr.write("SCAN_STATUS: ERROR\n")
        sys.stderr.flush()
        
        sys.stdout.write(f"CRITICAL ERROR: {error_msg}\n")
        sys.stdout.write(f"Error details: {traceback.format_exc()}\n")
        sys.stdout.write("Process failed with critical error\n")
        sys.stdout.flush()
        
        time.sleep(2)
        
        if log_manager:
            log_manager.log_error(f"CRITICAL_ERROR: {error_msg}", {
                'error_type': type(e).__name__,
                'error_details': str(e)
            })
        
        if config and hasattr(config, 'error_logger'):
            config.error_logger.has_errors = True
            config.error_logger.error_logger.error(f"CRITICAL_ERROR: {error_msg}")
        
        if exception_logger:
            exception_logger.log_exception(e, "main_function_critical_error", {
                'yarafile_provided': yarafile is not None,
                'scan_folder_provided': scan_folder is not None,
                'config_initialized': config is not None
            })

        try:
            logging.error(error_msg)
        except Exception:
            pass
        
        try:
            if webhook_uploader:
                standard_log = create_standard_log(
                    log_type='scan_completion_summary',
                    hostname=config.hostname if config else "unknown",
                    os_info=config.os_info if config else "unknown",
                    ip_address=config.ip_addresses[0] if config and config.ip_addresses else "unknown",
                    scan_id=config.scan_id if config else "unknown",
                    message="Scan failed with critical error",
                    level="ERROR",
                    data={
                        'status': 'critical_error',
                        'error_message': error_msg,
                        'error_type': type(e).__name__
                    }
                )
                webhook_uploader._queue_standard_upload(standard_log, priority=True)
        except Exception:
            pass

        failed_rules = config.error_logger.failed_rules_count if config and hasattr(config, 'error_logger') else 0
        files_scanned = scanner.files_scanned if 'scanner' in locals() else 0
        matches = scanner.total_detections if 'scanner' in locals() else 0

        # A crash reaching here IS a failed scan - record it so the finally-block's
        # scan_summary derives outcome="failed" instead of defaulting to "completed".
        # Without this the JSON contradicts the SCAN_RESULT line, and any tool trusting
        # the summary reads a crashed run as a clean one. (XDR does the same.)
        if 'scanner' in locals() and scanner is not None:
            try:
                scanner.scan_failed = True
                scanner.failure_reasons.append(f"Critical scanner error: {type(e).__name__}")
            except Exception:
                pass

        error_summary = (f"Scan failed: {files_scanned} files scanned | "
                        f"{failed_rules} rules failed compilation | "
                        f"{matches} matches found | Critical error occurred")
        
        return error_summary
        
    finally:
        try:
            if stats_manager:
                stats_manager.stop_monitoring()
            if 'scanner' in locals() and hasattr(scanner, "results_uploader") and scanner.results_uploader:
                scanner.results_uploader.stop(wait=True)
            if webhook_uploader:
                webhook_uploader.stop_uploader()

            # Machine-readable per-run summary, written AFTER the uploaders drain so the
            # delivery counts are final, and BEFORE stop_logging() so its own "summary
            # written" line still reaches the logs. NOTE: `scanner` is not pre-initialized
            # in this edition, so the locals() guard is the correct check here (unlike the
            # XDR edition, which sets scanner = None up front).
            if log_manager and config is not None and 'scanner' in locals() and scanner is not None:
                try:
                    if getattr(scanner, "cancel_requested", False):
                        _outcome = "cancelled"
                    elif getattr(scanner, "scan_failed", False):
                        _outcome = "failed"
                    else:
                        _outcome = "completed"
                    _dur = (scan_total_time if 'scan_total_time' in locals()
                            else (time.time() - scan_start_time) if 'scan_start_time' in locals()
                            else None)
                    _el = getattr(config, "error_logger", None)
                    _det = getattr(scanner, "detection_counts", {}) or {}
                    _ru = getattr(scanner, "results_uploader", None)
                    _match_books = _ru.get_upload_stats() if _ru else {}
                    _wh = {}
                    try:
                        if webhook_uploader:
                            _wh = (webhook_uploader.get_upload_statistics() or {}).get("summary", {}) or {}
                    except Exception:
                        pass
                    log_manager.write_scan_summary({
                        "outcome": _outcome,
                        "failure_reasons": list(getattr(scanner, "failure_reasons", []) or []),
                        "scan_folder": getattr(config, "scan_folder", None),
                        "scan_targets": list(getattr(scanner, "scan_targets", []) or []),
                        "excluded_targets": list(getattr(scanner, "excluded_targets", []) or []),
                        "duration_secs": round(_dur, 2) if _dur is not None else None,
                        "files_scanned": getattr(scanner, "files_scanned", None),
                        "files_skipped": getattr(scanner, "files_skipped", None),
                        "matches": getattr(scanner, "total_detections", None),
                        "unique_rules_triggered": len(_det),
                        "failed_rules": getattr(_el, "failed_rules_count", None),
                        "valid_rules": getattr(_el, "valid_rules_count", None),
                        "skipped_rules": getattr(_el, "skipped_rules_count", 0),
                        "scan_rate_fps": (round(getattr(scanner, "files_scanned", 0) / _dur, 2)
                                          if _dur and _dur > 0 else 0),
                        # Delivery books. match_delivery is the findings channel (one item
                        # per rule/file finding); telemetry_delivery is everything else.
                        "match_delivery": _match_books,
                        "telemetry_delivery": _wh,
                    })
                except Exception as _summary_err:
                    try:
                        log_manager.log_error(f"Scan summary write failed: {_summary_err}")
                    except Exception:
                        pass

            if log_manager:
                log_manager.stop_logging()
        except Exception as cleanup_error:
            sys.stderr.write(f"Error during final cleanup: {cleanup_error}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    try:
        yarafile_arg = None
        scan_folder_arg = None
        alert_severity_arg = "low"

        if len(sys.argv) > 1:
            yarafile_arg = sys.argv[1] if sys.argv[1].strip() else None

        if len(sys.argv) > 2:
            scan_folder_arg = sys.argv[2] if sys.argv[2].strip() else None

        if len(sys.argv) > 3:
            alert_severity_arg = _parse_alert_severity(sys.argv[3], "alert_severity")

        # `cancel` as argv[1] delivers a cooperative cancel to a running scan instead of
        # starting one - the CLI counterpart of the zero-input cancel() entry point.
        if (yarafile_arg or "").strip().lower() == "cancel":
            result = cancel()
        else:
            result = main(
                yarafile_arg,
                scan_folder_arg,
                alert_severity_arg,
            )

        result_text = str(result or "")
        # Print it. Previously main()'s return value was computed, used for the exit code,
        # and then thrown away - so a direct run (customer validation, scheduled task, CI)
        # exited silently having reported nothing at all. The only path that ever printed
        # was the Action Center snippet footer. Use the same "SCAN_RESULT: " prefix as that
        # footer so downstream parsing is identical on both paths.
        print("SCAN_RESULT: " + result_text)
        sys.stdout.flush()
        # "SCAN ABORTED" (placeholder credentials, nothing scanned or ingested) must not
        # exit 0 - it previously did, because only the "scan failed" prefix was checked.
        # "Cancel failed" covers the cancel entry point's own error return.
        _rt = result_text.lower()
        is_success = bool(result_text) and not (
            _rt.startswith("scan failed")
            or _rt.startswith("scan aborted")
            or _rt.startswith("cancel failed")
        )
        sys.exit(0 if is_success else 1)

    except Exception as e:
        error_msg = f"Critical startup error: {str(e)}"
        sys.stderr.write(f"{error_msg}\n")
        sys.stderr.write(f"Full traceback:\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        sys.exit(1)
