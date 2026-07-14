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
"""

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
if platform.system() == "Windows":
    from ctypes import wintypes

# Third-party imports
import psutil
import requests
import yara

# ============================================================================
# CONSTANTS
# ============================================================================

UPLOAD_RESULTS = True  # Match and telemetry uploads to webhook
UPLOAD_NON_MATCH_DATA = True  # Keep telemetry uploads enabled in webhook mode
DEFAULT_TIMEOUT_SECS = 20            # increased request timeout everywhere
MAX_RETRIES_PER_ITEM = 2             # hard cap to avoid infinite loops
BASE_BACKOFF_SECS = 1.0              # initial backoff
MAX_BACKOFF_SECS = 30.0              # backoff ceiling
CIRCUIT_FAILURE_THRESHOLD = 5        # open after N consecutive failures
CIRCUIT_RESET_TIMEOUT_SECS = 40      # stay open before probing again
WORKER_GET_TIMEOUT_SECS = 2.0        # queue.get timeout to allow graceful exit checks
THREAD_CLEANUP_TIMEOUT = 60          # Maximum time to wait for thread cleanup


DEFAULT_API_KEY = "http_collector_key"
DEFAULT_API_ENDPOINT = "http_collector_api"

API_KEY = DEFAULT_API_KEY
API_ENDPOINT = DEFAULT_API_ENDPOINT

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


def _get_webhook_endpoint(api_endpoint: str) -> str:
    """Return the configured webhook endpoint, normalized for requests."""
    return (api_endpoint or "").strip()


def _parse_bool_arg(value, arg_name="argument"):
    """Parse strict boolean CLI/runtime argument from text."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "y", "on"):
        return True
    if text in ("false", "0", "no", "n", "off"):
        return False

    raise ValueError(f"Invalid {arg_name} '{value}'. Use true or false.")


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


def _serialize_matches(yara_matches):
    """Convert YARA match objects to JSON-serializable format."""
    serial = []
    for m in yara_matches:
        normalized_strings = _normalize_match_strings(getattr(m, "strings", []) or [])
        serial.append({
            "rule": getattr(m, "rule", None),
            "tags": list(getattr(m, "tags", []) or []),
            "meta": dict(getattr(m, "meta", {}) or {}),
            "strings": [
                (int(o), str(sid), data.hex() if isinstance(data, (bytes, bytearray)) else str(data))
                for (o, sid, data) in normalized_strings
            ]
        })
    return serial


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
    
    def to_json(self):
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


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
class FileCacher:
    """Thread-safe hybrid cache (LRU in RAM + full on disk) for scan results."""

    def __init__(self, cache_file_path):
        self.cache_file = cache_file_path
        self.max_memory_entries = self._calculate_cache_size()
        self.memory_cache = OrderedDict()
        self.disk_cache = {}
        self.lock = threading.RLock()
        self.dirty = False
        self._stop_evt = threading.Event()
        self.log_manager = None

        self._load_cache()
        self._save_thread = threading.Thread(target=self._periodic_save, daemon=True)
        self._save_thread.start()

    def _calculate_cache_size(self):
        """Calculate cache size based on available RAM."""
        try:
            total_ram_gb = psutil.virtual_memory().total / (1024**3)
            if total_ram_gb >= 32:
                return 500_000
            if total_ram_gb >= 16:
                return 250_000
            if total_ram_gb >= 8:
                return 125_000
            if total_ram_gb >= 4:
                return 62_500
            return 25_000
        except Exception:
            return 25_000

    def _fast_signature(self, file_key, data_json_safe: dict) -> int:
        """Generate fast CRC32 signature for cache integrity."""
        content = f"{file_key}:{json.dumps(data_json_safe, sort_keys=True)}"
        return zlib.crc32(content.encode()) & 0xFFFFFFFF

    def put(self, file_key: str, scan_result: dict):
        """Store scan result in cache."""
        cache_entry = {
            'matches': scan_result.get('matches', []),
            'file_size': scan_result.get('file_size', 0),
            'timestamp': scan_result.get('timestamp', time.time()),
        }
        cache_entry['sig'] = self._fast_signature(file_key, {
            'matches': cache_entry['matches'],
            'file_size': cache_entry['file_size'],
            'timestamp': cache_entry['timestamp'],
        })

        with self.lock:
            if file_key in self.memory_cache:
                self.memory_cache.move_to_end(file_key)
                self.memory_cache[file_key] = cache_entry
            else:
                if len(self.memory_cache) >= self.max_memory_entries:
                    self.memory_cache.popitem(last=False)
                self.memory_cache[file_key] = cache_entry

            self.disk_cache[file_key] = cache_entry
            self.dirty = True

    def get(self, file_key: str):
        """Retrieve scan result from cache with integrity check."""
        with self.lock:
            entry = self.memory_cache.get(file_key)
            if entry is not None:
                self.memory_cache.move_to_end(file_key)
            else:
                entry = self.disk_cache.get(file_key)
                if entry is None:
                    return None
                self.memory_cache[file_key] = entry
                if len(self.memory_cache) > self.max_memory_entries:
                    self.memory_cache.popitem(last=False)

            stored_sig = entry.get('sig', 0)
            entry_copy = {k: v for k, v in entry.items() if k != 'sig'}
            calc_sig = self._fast_signature(file_key, entry_copy)

            if stored_sig != calc_sig:
                return None
            return entry

    def get_cache_stats(self):
        """Get current cache statistics."""
        with self.lock:
            approx_bytes = len(self.memory_cache) * 400
            return {
                'memory_entries': len(self.memory_cache),
                'disk_entries': len(self.disk_cache),
                'memory_usage_mb': round(approx_bytes / (1024*1024), 1),
                'dirty': self.dirty,
            }

    def stop_cache(self):
        """Stop cache and persist final state."""
        self._stop_evt.set()
        try:
            self._save_cache()
        finally:
            if getattr(self, "_save_thread", None):
                self._save_thread.join(timeout=2.0)
            if getattr(self, "log_manager", None):
                try:
                    self.log_manager.log_system("Cache stopped and saved")
                except Exception:
                    pass

    def _load_cache(self):
        """Load cache from disk."""
        if not self.cache_file or not os.path.exists(self.cache_file):
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.disk_cache = data
        except Exception:
            self.disk_cache = {}

    def _save_cache(self):
        """Save cache to disk atomically."""
        with self.lock:
            if not self.dirty:
                return
            tmp = self.cache_file + ".tmp"
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.disk_cache, f, ensure_ascii=False)
            try:
                os.replace(tmp, self.cache_file)
            finally:
                if os.path.exists(tmp):
                    try: 
                        os.remove(tmp)
                    except Exception:
                        pass
            self.dirty = False

    def _periodic_save(self):
        """Background thread for periodic cache persistence."""
        while not self._stop_evt.wait(60):
            try:
                self._save_cache()
            except Exception:
                pass


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

    def get_exception_count(self):
        """Get total number of exceptions logged."""
        return self.exception_count


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
        
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'memory_usage_mb': 0
        }
        
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

    def update_cache_stats(self, hits=0, misses=0, evictions=0, memory_usage_mb=0):
        """Update cache performance statistics."""
        with self.lock_stats:
            self.cache_stats['hits'] += hits
            self.cache_stats['misses'] += misses
            self.cache_stats['evictions'] += evictions
            self.cache_stats['memory_usage_mb'] = memory_usage_mb

        if (self.cache_stats['hits'] + self.cache_stats['misses']) % 100 == 0:
            hit_rate = self.cache_stats['hits'] / (self.cache_stats['hits'] + self.cache_stats['misses']) * 100

            if self.log_manager is not None:
                self.log_manager.log_cache_performance(
                    hit_rate,
                    self.cache_stats['hits'] + self.cache_stats['misses'],
                    self.cache_stats['memory_usage_mb']
                )

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
            self.stats_logger.info(f"Cache Statistics: {json.dumps(self.cache_stats, indent=2)}")
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
                'cache_stats': self.cache_stats.copy(),
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

                self._upload_standard_log(standard_log)
                self.webhook_queue.task_done()

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

    def _upload_standard_log(self, standard_log: StandardLogEntry):
        """Upload standardized log entry to webhook."""
        try:
            headers = {
                "Authorization": API_KEY,
                "Content-Type": "application/json"
            }

            response = requests.post(
                url=_get_webhook_endpoint(API_ENDPOINT),
                headers=headers,
                json=standard_log.to_dict(),
                timeout=10,
            )

            if 200 <= response.status_code < 300:
                self.upload_stats['successful_uploads'] += 1
            else:
                self.upload_stats['failed_uploads'] += 1
                self.loggers[LogType.UPLOAD].error(
                    f"Webhook upload failed (HTTP {response.status_code}): {response.text}"
                )

        except Exception as e:
            self.upload_stats['failed_uploads'] += 1
            self.loggers[LogType.UPLOAD].error(
                f"Webhook upload error for {standard_log.type}: {e}"
            )

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
        progress_data = {
            'files_scanned': files_scanned,
            'files_skipped': files_skipped,
            'total_detections': detections,
            'queue_size': queue_size,
            'scan_rate_files_per_sec': scan_rate,
            'metrics': additional_metrics or {}
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

    def log_cache_performance(self, hit_rate: float, total_requests: int, 
                             memory_usage_mb: float):
        """Log cache performance metrics."""
        cache_data = {
            'hit_rate_percent': hit_rate,
            'total_requests': total_requests,
            'memory_usage_mb': memory_usage_mb
        }
        
        message = (
            f"Cache Performance | Hit Rate: {hit_rate:.1f}% | "
            f"Requests: {total_requests} | Memory: {memory_usage_mb:.1f}MB"
        )
        
        self.log_statistics(message, cache_data)

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

    def stop_logging(self):
        """Stop all logging activities."""
        if self._stopped:
            return
        self._stopped = True
        if self.webhook_thread and self.webhook_thread.is_alive():
            max_wait_time = THREAD_CLEANUP_TIMEOUT
            start_wait = time.time()
            initial_queue_size = self.webhook_queue.qsize()
            if initial_queue_size > 0:
                self.log_upload(
                    f"Waiting for {initial_queue_size} pending standardized log uploads (max {max_wait_time}s)..."
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
                'monitoring_duration_minutes': (time.time() - self.system_boot_time) / 60
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
        # Roadmap Feature: Caching is disabled by default
        self.use_cache = False
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
        os.makedirs(self.scanner_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)

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
            "Light profile active: cache disabled, reduced workers, reduced monitoring, and lower-impact scan execution"
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
        self.scan_id = f"yara_{yara_hash}"
        self.error_logger.error_logger.info(f"Scan ID (YARA hash): {self.scan_id}")

        self.cleanup_script = os.path.join(
            self.scanner_dir, "cleanup_script.bat" if is_windows else "cleanup_script.sh"
        )
        self.file_mapping = os.path.join(self.evidence_dir, "file_mapping.txt")
        self.output_log = os.path.join(self.logs_dir, f"scanner_{self.run_id}.log")

        self.max_file_mb = int(os.getenv("YARA_MAX_MB", "64") or 64)
        self.max_file_bytes = self.max_file_mb * 1024 * 1024 if self.max_file_mb else 0

        cpu_count = os.cpu_count() or 2
        default_workers = 1 if cpu_count <= 2 else 2
        configured_workers = int(os.getenv("YARA_THREADS", str(default_workers)) or default_workers)
        self.max_workers = max(1, min(2, configured_workers))
        self.scan_queue_size = max(
            2, int(os.getenv("YARA_QUEUE_SIZE", str(self.max_workers * 2)) or (self.max_workers * 2))
        )
        self.log_interval = int(os.getenv("YARA_PROGRESS_LOG_SECS", "120") or 120)
        self.enable_performance_monitoring = str(
            os.getenv("YARA_ENABLE_PERF_MONITOR", "false")
        ).strip().lower() in ("1", "true", "yes", "on")
        self.enable_resource_monitoring = str(
            os.getenv("YARA_ENABLE_RESOURCE_MONITOR", "false")
        ).strip().lower() in ("1", "true", "yes", "on")
        self.enable_fd_monitoring = str(
            os.getenv("YARA_ENABLE_FD_MONITOR", "false")
        ).strip().lower() in ("1", "true", "yes", "on")
        self.track_real_paths = False
        self.light_throttle_enabled = True
        self.throttle_check_interval_secs = float(os.getenv("YARA_LIGHT_THROTTLE_CHECK_SECS", "0.5") or 0.5)
        self.high_cpu_threshold = float(os.getenv("YARA_LIGHT_HIGH_CPU", "80") or 80)
        self.critical_cpu_threshold = float(os.getenv("YARA_LIGHT_CRITICAL_CPU", "90") or 90)
        self.throttle_sleep_secs = float(os.getenv("YARA_LIGHT_SLEEP_SECS", "0.02") or 0.02)
        self.critical_throttle_sleep_secs = float(
            os.getenv("YARA_LIGHT_CRITICAL_SLEEP_SECS", "0.08") or 0.08
        )
        self.queue_backoff_secs = float(os.getenv("YARA_QUEUE_BACKOFF_SECS", "0.25") or 0.25)
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
            "/appdata/local/google/chrome/user data/default/cache/",
            "/appdata/local/microsoft/edge/user data/default/cache/",
            "/mozilla/firefox/profiles/",
            "/cache2/",
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
                "C:\\yara_scanner\\",
                "C:\\$Recycle.Bin",
                "C:\\System Volume Information",
                self.scanner_dir,
            ]
            self.win_skip_patterns = [
                "C:\\yara_scanner\\*",
                "C:\\*\\cyvera\\*"
            ]
            self.win_skip_folder = [os.path.normpath(path.lower()) for path in self.win_skip_folder]
            self.win_skip_patterns = [pattern.lower() for pattern in self.win_skip_patterns]
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
            self.skip_paths = set(self.mac_skip_directory)
        
        else:
            self.lin_skip_directory = []
            self.mac_skip_directory = []
            self.skip_paths = set()

        self.batch_size = 1000
        self.performance_log_interval = 120
        self.statistics_upload_interval = 60

        if self.scan_folder and self.scan_folder.lower() != "default":
            if not os.path.isdir(self.scan_folder):
                raise ValueError(f"Specified scan folder is not a valid directory: {self.scan_folder}")
            self.scan_targets = [os.path.abspath(self.scan_folder)]
            self.error_logger.error_logger.info(f"Scan limited to folder: {self.scan_targets[0]}")
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
        self.results = []
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id
        self.date_of_scan = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.log_manager = None

        self.results_file = os.path.join(
            self.config.evidence_dir, f"yara_matches_{self.hostname}_{self.config.run_id}.json"
        )
        
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

                self._upload_standard_result(standard_log)
                self.upload_queue.task_done()

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

    def _upload_standard_result(self, standard_log: StandardLogEntry):
        """Upload YARA match with bounded retries."""
        headers = {
            "Authorization": API_KEY,
            "Content-Type": "application/json"
        }
        payload = standard_log.to_dict()
        endpoint = _get_webhook_endpoint(API_ENDPOINT)

        attempt = 0
        while attempt < MAX_RETRIES_PER_ITEM:
            attempt += 1
            try:
                resp = requests.post(
                    url=endpoint,
                    headers=headers,
                    json=payload,
                    timeout=DEFAULT_TIMEOUT_SECS,
                )
                if 200 <= resp.status_code < 300:
                    self.upload_stats['successful_uploads'] += 1
                    self._throttled_log("upload_ok",
                                        f"YARA match upload successful (HTTP {resp.status_code})", level="upload")
                    return True

                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    delay = _exp_backoff_delay(attempt)
                    self._throttled_log("upload_retry",
                                        f"Upload failed (HTTP {resp.status_code}). Retrying in {delay:.1f}s "
                                        f"(attempt {attempt}/{MAX_RETRIES_PER_ITEM}).", level="upload")
                    time.sleep(delay)
                    continue

                self.upload_stats['failed_uploads'] += 1
                self._throttled_log("upload_err",
                                    f"YARA match upload failed (HTTP {resp.status_code}): {resp.text[:200]}")
                return False

            except (requests.Timeout, requests.ConnectionError) as e:
                delay = _exp_backoff_delay(attempt)
                self._throttled_log("upload_neterr",
                                    f"Network error uploading result: {str(e)[:160]}. Retrying in {delay:.1f}s "
                                    f"(attempt {attempt}/{MAX_RETRIES_PER_ITEM}).", level="upload")
                time.sleep(delay)

            except Exception as e:
                self.upload_stats['failed_uploads'] += 1
                self._throttled_log("upload_err", f"YARA match upload unexpected error: {e}")
                return False

        self.upload_stats['failed_uploads'] += 1
        self._throttled_log("upload_err", "Max retries reached for payload. Abandoning.")
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
                max_wait_time = THREAD_CLEANUP_TIMEOUT
                start_wait = time.time()
                initial_queue_size = self.upload_queue.qsize()
                if initial_queue_size > 0 and self.log_manager:
                    self.log_manager.log_upload(
                        f"Waiting for {initial_queue_size} pending match uploads (max {max_wait_time}s)..."
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
        """Add YARA match and queue for upload."""
        raw_matches = list(match_data or [])
        fallback_text = str(fallback_detail or "").strip()
        upload_entries = raw_matches or [
            (None, None, fallback_text or "Condition-only YARA match; no string instances were produced.")
        ]
        match_count = 0
        for string_id, offset, string_data in upload_entries:
            is_rule_only_match = string_id is None and offset is None

            if string_data is None:
                string_data = ""
            else:
                string_data = _render_match_data(string_data)

            result = {
                "hostname": self.hostname,
                "os_info": self.os_info,
                "ipAddress": self.ip_address,
                "dateOfScan": self.date_of_scan,
                "filename": filename,
                "rule": rule,
                "threat_level": getattr(self.config, "alert_severity", "low"),
                "string": string_data,
                "offset": "" if offset is None else str(offset),
                "match": "" if string_id is None else str(string_id),
                "match_scope": "rule" if is_rule_only_match else "string",
                "string_match_count": len(raw_matches),
                "file_sha256": file_sha256,
                "file_creation_time": file_creation_time,
            }
            self.results.append(result)
            self.upload_stats['total_matches'] += 1
            match_count += 1
            
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
                            else f"YARA match: rule '{rule}' in {filename}"
                        ),
                        level="INFO",
                        data={
                            'filename': filename,
                            'rule': rule,
                            'threat_level': getattr(self.config, "alert_severity", "low"),
                            'string': string_data,
                            'offset': "" if offset is None else str(offset),
                            'match': "" if string_id is None else str(string_id),
                            'match_scope': "rule" if is_rule_only_match else "string",
                            'string_match_count': len(raw_matches),
                            'dateOfScan': self.date_of_scan,
                            'file_sha256': file_sha256,
                            'file_creation_time': file_creation_time
                        }
                    )
                    self.upload_queue.put(standard_log, timeout=1.0)
                    if self.log_manager:
                        if is_rule_only_match:
                            self.log_manager.log_upload(
                                f"Queued rule-only match for upload: rule='{rule}'"
                            )
                        else:
                            self.log_manager.log_upload(
                                f"Queued match for upload: rule='{rule}', offset={offset}"
                            )
                except Exception:
                    if self.log_manager:
                        self.log_manager.log_upload("Upload queue full - skipping real-time upload for match")
        
        if self.log_manager:
            self.log_manager.log_upload(
                f"Added {match_count} uploadable entries for rule '{rule}' in file: {filename} "
                f"(string matches: {len(raw_matches)})"
            )

    def save_results(self):
        """Save results to JSON file."""
        if self.log_manager:
            self.log_manager.log_upload(f"Attempting to save {len(self.results)} results to: {self.results_file}")
        
        if not self.results:
            if self.log_manager:
                self.log_manager.log_upload("No results to save")
            return True

        try:
            with open(self.results_file, "w", encoding="utf-8") as f:
                for result in self.results:
                    f.write(json.dumps(result, ensure_ascii=False) + "\n")

            if self.log_manager:
                self.log_manager.log_upload(f"Successfully saved {len(self.results)} results to: {self.results_file}")
            return True
            
        except Exception as e:
            if self.log_manager:
                self.log_manager.log_error(f"Error saving results to JSON: {e}")
            return False
    
    def upload_results(self):
        """Finalize upload process with timeout protection."""
        if self.log_manager:
            self.log_manager.log_upload("FINALIZING UPLOAD PROCESS")
        
        if self.upload_thread and self.upload_thread.is_alive():
            if self.log_manager:
                self.log_manager.log_upload("Stopping real-time upload thread...")
            
            max_wait_time = 15
            start_wait = time.time()
            initial_queue_size = self.upload_queue.qsize()
            
            if initial_queue_size > 0 and self.log_manager:
                self.log_manager.log_upload(f"Waiting for {initial_queue_size} pending uploads (max {max_wait_time}s)...")
            
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
        
        self.save_results()
        
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
            'cache_stats': 90,
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

                self._process_standard_upload(standard_log)
                self.upload_queue.task_done()

            except Empty:
                if self.stop_upload_thread:
                    break
                continue
            except Exception:
                continue

        self.log_manager.log_upload("Webhook upload worker thread stopped")

    def _process_standard_upload(self, standard_log: StandardLogEntry):
        """Process and upload standardized log entry with retries + circuit breaker."""
        try:
            data_type = standard_log.type
            self.upload_stats[data_type]['total'] += 1

            headers = {
                "Authorization": API_KEY,
                "Content-Type": "application/json"
            }

            if not self._circuit.allow():
                try:
                    self.upload_queue.put(standard_log, timeout=1.0)
                except Exception:
                    pass
                time.sleep(2.0)
                return

            attempt = 0
            sent_ok = False
            while attempt < MAX_RETRIES_PER_ITEM:
                attempt += 1
                try:
                    response = requests.post(
                        url=_get_webhook_endpoint(API_ENDPOINT),
                        headers=headers,
                        json=standard_log.to_dict(),
                        timeout=DEFAULT_TIMEOUT_SECS
                    )

                    if 200 <= response.status_code < 300:
                        sent_ok = True
                        self._circuit.on_success()
                        break

                    if response.status_code in (408, 429, 500, 502, 503, 504):
                        delay = _exp_backoff_delay(attempt)
                        time.sleep(delay)
                        continue

                    self._circuit.on_failure()
                    break

                except (requests.Timeout, requests.ConnectionError):
                    delay = _exp_backoff_delay(attempt)
                    time.sleep(delay)
                except Exception as e:
                    self._circuit.on_failure()
                    self.log_manager.log_error(f"Webhook unexpected error for {data_type}: {str(e)}")
                    break

            if sent_ok:
                self.upload_stats[data_type]['successful'] += 1
            else:
                self.upload_stats[data_type]['failed'] += 1

        except Exception as e:
            data_type = standard_log.type if hasattr(standard_log, 'type') else 'unknown'
            self.upload_stats[data_type]['failed'] += 1
            self.log_manager.log_error(f"Webhook upload error for {data_type}: {str(e)}")

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
                max_wait_time = THREAD_CLEANUP_TIMEOUT
                start_wait = time.time()
                initial_queue_size = self.upload_queue.qsize()
                if initial_queue_size > 0:
                    self.log_manager.log_upload(
                        f"Waiting for {initial_queue_size} pending telemetry uploads (max {max_wait_time}s)..."
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
        """Create ZIP file containing evidence."""
        with zipfile.ZipFile(
            self.config.evidence_zip, "w", zipfile.ZIP_DEFLATED
        ) as zip_file:
            for file_path, file_hash in self.file_hashes.items():
                try:
                    zip_file.write(file_path, f"matched_files/{file_hash}")
                except Exception as e:
                    logging.error(f"Error adding file to zip {file_path}: {e}")

            for alert_file in os.listdir(self.config.alert_dir):
                if alert_file.endswith(".txt"):
                    alert_path = os.path.join(self.config.alert_dir, alert_file)
                    zip_file.write(alert_path, f"alerts/{alert_file}")

            zip_file.write(self.config.file_mapping, "file_mapping.txt")


class CleanupManager:
    """Manages cleanup of scan artifacts."""
    
    def __init__(self, config):
        self.config = config

    def _extract_run_id_from_log_name(self, filename):
        """Extract scan run_id from standardized log filename."""
        match = re.search(r'_(\d{8}_\d{6}_\d{6})\.log$', filename)
        return match.group(1) if match else None

    def _prune_old_scan_logs(self, keep_scans=2):
        """Keep logs for only the latest N scans (by run_id timestamp)."""
        logs_dir = self.config.logs_dir
        if not os.path.isdir(logs_dir):
            return

        run_logs = defaultdict(list)
        for name in os.listdir(logs_dir):
            if not name.endswith(".log"):
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
        
        self.scanned_real_paths = set()
        self.junction_skip_count = 0
        self.lock_real_paths = threading.Lock()

        # Roadmap Feature: Initialize file cache if enabled
        self.file_cache = None
        if self.config.use_cache:
            cache_file_path = os.path.join(self.config.scanner_dir, "scan_cache.json")
            self.file_cache = FileCacher(cache_file_path)
            self.file_cache.log_manager = self.log_manager

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
                'cache_enabled': self.config.use_cache,
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

    def _is_valid_rule_structure(self, content, rule_name):
        """Basic validation for YARA rule structure."""
        try:
            if not re.search(r'\bcondition\s*:', content, re.IGNORECASE):
                logging.debug(f"Rule {rule_name} missing condition section")
                return False
            
            if not re.match(r'^\s*(?:(?:private|global)\s+)*rule\s+\w+', content, re.IGNORECASE):
                logging.debug(f"Rule {rule_name} missing rule declaration line")
                return False
            
            return True
            
        except Exception as e:
            logging.debug(f"Validation error for rule {rule_name}: {e}")
            return False
    
    def _get_available_yara_modules(self):
        """Detect which YARA modules are available."""
        test_modules = ['pe', 'elf', 'cuckoo', 'magic', 'hash', 'math', 'dotnet', 'time']
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
        available_modules = self._get_available_yara_modules()
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
        
        if skipped_count > 0:
            error_logger.error_logger.info(f"Skipped {skipped_count} rules due to unavailable modules")

        if not valid_sources:
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
    
    def _get_scanner_stats(self):
        """Get comprehensive scanner statistics."""
        with self.lock_counts:
            base_stats = {
                'files_scanned': self.files_scanned,
                'files_skipped': self.files_skipped,
                'total_detections': self.total_detections,
                'last_scanned_file': self.last_scanned_file,
                'targets': self.scan_targets,
                'valid_rules_count': self.config.error_logger.valid_rules_count,
                'failed_rules_count': self.config.error_logger.failed_rules_count,
            }
            
            if hasattr(self, 'stats_manager'):
                performance_data = self.stats_manager.get_current_stats_for_upload()
                base_stats.update({
                    'performance_metrics': performance_data.get('performance_metrics', {}),
                    'cache_stats': performance_data.get('cache_stats', {}),
                    'scan_estimates': performance_data.get('scan_estimates', {}),
                    'worker_count': len(self.stats_manager.worker_stats),
                    'performance_snapshots': len(self.stats_manager.performance_history)
                })
            
            if getattr(self, 'resource_monitor', None) is not None:
                resource_summary = self.resource_monitor.get_resource_summary()
                base_stats.update({
                    'resource_monitoring': resource_summary,
                    'resource_alerts': len(self.resource_monitor.alert_history)
                })
            
            if hasattr(self, 'webhook_uploader'):
                upload_stats = self.webhook_uploader.get_upload_statistics()
                base_stats.update({
                    'webhook_stats': upload_stats
                })
            
            return base_stats

    def _calculate_cache_hit_rate(self):
        """Calculate current cache hit rate."""
        cache_stats = self.stats_manager.cache_stats
        total_requests = cache_stats['hits'] + cache_stats['misses']
        if total_requests > 0:
            return (cache_stats['hits'] / total_requests) * 100
        return 0

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
                self._write_alerts(
                    matches,
                    file_path,
                    file_sha256=content_hash,
                    file_creation_time=file_creation_time
                )
                with self.lock_files:
                    self.evidence_collector.add_matched_file(file_path, file_sha256=content_hash)
                
                self.log_manager.log_alert(
                    f"YARA matches found in {file_path}",
                    {
                        'file_path': file_path,
                        'real_path': real_path,
                        'file_size': st.st_size,
                        'file_sha256': content_hash,
                        'file_creation_time': file_creation_time,
                        'match_count': len(matches),
                        'rules_matched': [_iter_hit_fields(m)[0] for m in matches]
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
            return False, str(e)
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
        if any(fragment in portable_path for fragment in self.config.skip_path_fragments):
            return True

        if platform.system() == "Windows":
            drive = os.path.splitdrive(normalized_path)[0].rstrip(":")
            if drive in self.config.win_skip_drive:
                return True

            for skip_folder in self.config.win_skip_folder:
                if normalized_path.startswith(skip_folder):
                    return True

            path_without_drive = os.path.splitdrive(normalized_path)[1]
            for pattern in self.config.win_skip_patterns:
                pattern_parts = (
                    pattern.replace("**\\", "").replace("\\**", "").split("\\")
                )
                pattern_parts = [p.lower() for p in pattern_parts if p]

                path_parts = path_without_drive.split("\\")
                path_parts = [p.lower() for p in path_parts if p]

                try:
                    idx = 0
                    for part in pattern_parts:
                        while idx < len(path_parts):
                            if path_parts[idx] == part:
                                break
                            idx += 1
                        if idx >= len(path_parts):
                            raise ValueError
                        idx += 1
                    return True
                except ValueError:
                    continue
            return False
        
        elif platform.system() == "Linux":
            return any(
                normalized_path.startswith(skip_dir)
                for skip_dir in self.config.lin_skip_directory
            )
        
        elif platform.system() == "Darwin":
            if any(normalized_path.startswith(skip_dir) for skip_dir in self.config.mac_skip_directory):
                return True
            
            filename = os.path.basename(normalized_path)
            if filename.startswith('._'):
                return True
            if filename == '.DS_Store':
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
                            f.write("Matched Strings:\n")
                            f.write("-" * 40 + "\n")
                            for (off, sid, data) in strings:
                                string_repr = _render_match_data(data)
                                f.write(f"String ID: {sid}\n")
                                f.write(f"Offset: {off}\n")
                                f.write(f"Data: {string_repr}\n")
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

        if hasattr(self, 'log_manager'):
            total_strings = sum(len(_iter_hit_fields(m)[3]) for m in matches)
            self.log_manager.log_alert(
                f"YARA detection event: {len(matches)} rules triggered in {os.path.basename(file_path)}",
                {
                    'file_path': file_path,
                    'file_sha256': file_sha256,
                    'file_creation_time': file_creation_time,
                    'rules_triggered': [_iter_hit_fields(m)[0] for m in matches],
                    'total_string_matches': total_strings,
                    'detections': file_detections,
                    'detection_timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
            )

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
                process = psutil.Process()
                cpu_percent = process.cpu_percent()
                memory_info = process.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                
                io_counters = process.io_counters()
                disk_io_mb = (io_counters.read_bytes + io_counters.write_bytes) / 1024 / 1024
                
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
                'cache_hit_rate': self._calculate_cache_hit_rate(),
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
            
            cache_stats = self.stats_manager.cache_stats
            if cache_stats['hits'] + cache_stats['misses'] > 0:
                hit_rate = (cache_stats['hits'] / (cache_stats['hits'] + cache_stats['misses'])) * 100
                self.log_manager.log_cache_performance(
                    hit_rate, cache_stats['hits'] + cache_stats['misses'],
                    cache_stats['memory_usage_mb']
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
        
        cache_stats = self.stats_manager.cache_stats
        if cache_stats['hits'] + cache_stats['misses'] > 0:
            final_hit_rate = (cache_stats['hits'] / (cache_stats['hits'] + cache_stats['misses'])) * 100
            self.log_manager.log_statistics(
                f"Final cache performance: {final_hit_rate:.1f}% hit rate",
                cache_stats
            )
        
    def _perform_enhanced_cleanup(self, start_time, total_files_found, files_per_target):
        """Enhanced cleanup with aggressive timeouts."""
        self.log_manager.log_system("=== ENHANCED CLEANUP AND FINALIZATION ===")
        self.status_uploader.set_status("finishing")
        
        cleanup_start = time.time()
       
        try:
            if hasattr(self, 'file_cache') and self.file_cache:
                self.file_cache.stop_cache()
                self.log_manager.log_system("File cache stopped and saved")
        except Exception as e:
            self.log_manager.log_error(f"Error stopping file cache: {e}")

        try:
            if getattr(self, 'resource_monitor', None) is not None:
                self.resource_monitor.stop_monitoring()
            self.stats_manager.stop_monitoring()
        except Exception as e:
            self.log_manager.log_error(f"Error stopping monitoring: {e}")
        
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
                'cache_enabled': self.config.use_cache
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
        self.log_manager.log_performance(
            f"Worker thread startup completed in {worker_startup_time:.2f} seconds",
            {'worker_startup_time_seconds': worker_startup_time, 'workers_started': len(self.scan_threads)}
        )

        last_log = time.time()
        last_comprehensive_stats = time.time()
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
                    
                    for root, dirs, files in os.walk(target):
                        if not self.scan_active:
                            break
                            
                        if self._is_special_file(root):
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
                                
                        current_time = time.time()
                        if current_time - last_log >= self.config.log_interval:
                            self._log_progress()
                            last_log = current_time
                            
                    target_scan_time = time.time() - target_start_time
                    files_per_target[target] = target_files_found
                    
                    self.log_manager.log_statistics(
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
            
            cache_total = scanner.stats_manager.cache_stats['hits'] + scanner.stats_manager.cache_stats['misses']
            if cache_total > 0:
                final_report_data['cache_performance'] = {
                    'hit_rate_percent': (scanner.stats_manager.cache_stats['hits'] / cache_total) * 100,
                    'total_requests': cache_total,
                    'evictions': scanner.stats_manager.cache_stats['evictions'],
                    'memory_usage_mb': scanner.stats_manager.cache_stats['memory_usage_mb']
                }
        
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
        _ep_bad = (not _ep) or (_ep == DEFAULT_API_ENDPOINT) or (not _ep.lower().startswith("http"))
        _key_bad = (not _key) or (_key == DEFAULT_API_KEY)
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
                
                if scan_folder and any(scan_folder.startswith(path) for path in system_paths):
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
            'cache_enabled': config.use_cache,
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
        if scanner.file_cache:
            scanner.file_cache.log_manager = log_manager

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
                'scan_errors': sum(1 for reason in scanner.skip_reasons.keys() if 'error' in reason.lower())
            }
        }
        
        standard_log = create_standard_log(
            log_type='scan_completion_summary',
            hostname=config.hostname,
            os_info=config.os_info,
            ip_address=config.ip_addresses[0] if config.ip_addresses else "Unknown",
            scan_id=config.scan_id,
            message=f"Scan completed successfully in {datetime.timedelta(seconds=int(scan_total_time))}",
            level="INFO",
            data=comprehensive_final_stats
        )
        webhook_uploader._queue_standard_upload(standard_log, priority=True)
        
        upload_final_comprehensive_report(scanner, scan_total_time)
        
        log_manager.log_statistics(
            f"SCAN COMPLETED SUCCESSFULLY in {datetime.timedelta(seconds=int(scan_total_time))}",
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

        summary = (f"Scan completed: {scanner.files_scanned} files scanned | "
                f"{error_logger.failed_rules_count} rules failed compilation | "
                f"{scanner.total_detections} matches found{upload_errors}")
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

        result = main(
            yarafile_arg,
            scan_folder_arg,
            alert_severity_arg,
        )

        result_text = str(result or "")
        is_success = bool(result_text) and not result_text.lower().startswith("scan failed")
        sys.exit(0 if is_success else 1)

    except Exception as e:
        error_msg = f"Critical startup error: {str(e)}"
        sys.stderr.write(f"{error_msg}\n")
        sys.stderr.write(f"Full traceback:\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        sys.exit(1)
