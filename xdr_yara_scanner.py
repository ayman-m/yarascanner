"""
YARA Scanner (XDR API Edition)
==================================
Enterprise-grade file scanner with real-time threat detection and Cortex XDR API reporting.

Features:
- Multi-threaded scanning with configurable workers
- Real-time Cortex XDR API alert insertion
- Scan caching for enhanced performance (Roadmap)
- Comprehensive logging and statistics
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

UPLOAD_RESULTS = True  # Match uploads to XDR
UPLOAD_NON_MATCH_DATA = False  # Keep non-match logs on disk only
DEFAULT_TIMEOUT_SECS = 20            # increased request timeout everywhere
MAX_RETRIES_PER_ITEM = 4             # per-item retry cap (Insert Parsed Alerts)
BASE_BACKOFF_SECS = 1.0              # initial backoff
MAX_BACKOFF_SECS = 30.0              # backoff ceiling
CIRCUIT_FAILURE_THRESHOLD = 5        # open after N consecutive failures
CIRCUIT_RESET_TIMEOUT_SECS = 40      # stay open before probing again
WORKER_GET_TIMEOUT_SECS = 2.0        # queue.get timeout to allow graceful exit checks
THREAD_CLEANUP_TIMEOUT = 60          # Maximum time to wait for thread cleanup


DEFAULT_XDR_API_KEY = "replace_with_xdr_standard_api_key"
DEFAULT_XDR_API_ID = "replace_with_xdr_standard_api_id"
DEFAULT_XDR_API_URL = "replace_with_xdr_standard_api_url"

# ============================================================================
# CUSTOMER CONFIG — set these ONCE for your deployment, then (re)upload/deliver
# the script. These are the per-run behaviour knobs; putting them here means an
# operator only supplies the essentials at run time — yarafile, scan_folder,
# alert_severity — instead of a long options string on every scan.
#
# Precedence: an explicit Action Center `options` value (key=value,key=value)
# still OVERRIDES the matching constant below, so per-run overrides remain
# possible without editing the script. Leave a value as-is to use it fleet-wide.
# ============================================================================
CONFIG_MODE = "scan"                    # "scan" (run a scan) or "cancel" (stop a running scan)
CONFIG_CREATE_ALERTS = True             # push one XDR alert per YARA match (feeds incidents)
CONFIG_WRITE_DATASET = True             # write the yara_scanner_* lookup datasets (dashboards)
CONFIG_COLLECT_FILES = False            # copy matched files into the evidence ZIP (off = metadata only)
CONFIG_THROTTLE_MODE = "script"         # CPU throttling: "script" | "os" | "off"
CONFIG_CPU_HIGH_THRESHOLD = None        # percent CPU to start pausing (e.g. 70); None = light-profile default
CONFIG_CPU_CRITICAL_THRESHOLD = None    # percent CPU to pause hard (e.g. 90); None = light-profile default
CONFIG_MAX_PAUSE_SECS = None            # cap cumulative throttle pause per scan (secs); None = default
CONFIG_TENANT_ID = ""                   # tag rows/alerts with this tenant id; "" = derive from API URL
CONFIG_LOOKUP_SHARD = "endpoint"        # dataset sharding: "endpoint" (per-host, recommended) | "none" | "<label>"
CONFIG_OPTIONS = ""                     # extra "key=value,key=value" overrides applied every run (rarely needed)
# ============================================================================

XDR_INSERT_PARSED_ALERTS_PATH = "/public_api/v1/alerts/insert_parsed_alerts"
XDR_LOOKUPS_ADD_DATA_PATH = "/public_api/v1/xql/lookups/add_data"
XDR_GET_DATASETS_PATH = "/public_api/v1/xql/get_datasets"
XDR_ADD_DATASET_PATH = "/public_api/v1/xql/add_dataset"
# XDR's lookups/add_data is NOT concurrency-safe server-side: it stages each write through a
# per-write BigQuery "clone" table, and concurrent writes to the SAME lookup dataset race with
# a transient HTTP 500 "...<dataset>_clone was not found". The server holds the dataset through
# a slow merge, so client-side time-spreading alone can't fix it (verified: even 45s of jitter
# across 8 writers to one dataset still lost 7/8). The REAL fix is per-writer dataset sharding
# (see LOOKUP_DATASET_SHARD) so no two writers ever touch the same dataset. The knobs below are
# secondary insurance for the rare case of two scans on the SAME host writing that host's shard:
#   FEWER posts  -> big batches + deferred partial flush (each POST is one collision chance).
#   DECORRELATE  -> small pre-write jitter spreads same-host writers.
#   RECOVER      -> full-jitter retries mop up the remainder.
LOOKUP_DATASET_BATCH_SIZE = int(os.environ.get("YARA_LOOKUP_BATCH", "500") or 500)  # rows per POST (<1000/10s limit)
LOOKUP_DATASET_FLUSH_SECS = float(os.environ.get("YARA_LOOKUP_FLUSH_SECS", "30") or 30)  # defer partials -> fewer POSTs
LOOKUP_WRITE_JITTER_SECS = float(os.environ.get("YARA_LOOKUP_WRITE_JITTER", "2") or 2)   # light same-host spread
LOOKUP_ADD_DATA_MAX_RETRIES = int(os.environ.get("YARA_LOOKUP_RETRIES", "6") or 6)
LOOKUP_DRAIN_TIMEOUT = float(os.environ.get("YARA_LOOKUP_DRAIN_SECS", "150") or 150)  # final-flush budget (covers jitter+retries)
# add_data merges are slow server-side (~10s/POST is normal), but a hung CONNECT shouldn't cost
# the full budget. (connect, read) tuple: fail fast on connect, stay patient on the slow read.
LOOKUP_POST_TIMEOUT = (5, float(os.environ.get("YARA_LOOKUP_READ_TIMEOUT", "30") or 30))
# THE fix for the add_data concurrency limitation: shard the lookup datasets per-writer so the
# server never sees two endpoints writing the SAME dataset at once (the only condition that
# triggers the clone-table race). Each endpoint writes yara_scanner_matches_<shard> and
# _scans_<shard>; dashboards fan back in with a wildcard: `dataset = yara_scanner_matches_* | ...`.
#   endpoint  -> one dataset per host (default; 1 writer per dataset -> 100% landing at any scale)
#   none      -> legacy single shared dataset (only safe when fleet concurrency is ~1)
#   <literal> -> force a specific shard label (e.g. a wave/site bucket)
LOOKUP_DATASET_SHARD = os.environ.get("YARA_LOOKUP_SHARD", "endpoint").strip() or "endpoint"
# Lookup datasets have a FIXED schema set at creation — XDR silently SKIPS rows that carry fields
# the existing dataset doesn't know about. So schema changes can't be applied in place; instead we
# tag the dataset name with a schema version and bump it whenever the row shape changes. A fresh
# version = a fresh dataset with the new schema; old-version datasets remain queryable (the
# dashboards' `yara_scanner_matches*` wildcard spans every version). Bump this on any schema edit.
LOOKUP_SCHEMA_VERSION = os.environ.get("YARA_LOOKUP_SCHEMA_VER", "2").strip() or "2"
# Rule-compilation DISK cache. Compiling a large pack (~500 rules) costs ~90s and is repeated on
# every run because the scanner is a fresh process per action. yara-python's rules.save()/load()
# lets us persist the compiled ruleset on the endpoint and skip the whole per-rule compile loop on
# a subsequent run with identical rules. The cache is keyed on the exact rule text + yara/platform
# version + externals + module availability + a format tag, so it can never load a stale or
# cross-version bundle; any load failure falls back to a fresh compile.
RULE_CACHE_ENABLED = (os.environ.get("YARA_RULE_CACHE", "1").strip().lower() not in ("0", "false", "no", ""))
RULE_CACHE_FORMAT = os.environ.get("YARA_RULE_CACHE_FORMAT", "1").strip() or "1"  # bump when compile logic changes
RULE_CACHE_MAX_FILES = int(os.environ.get("YARA_RULE_CACHE_MAX", "5") or 5)
RULE_CACHE_MAX_BYTES = int(float(os.environ.get("YARA_RULE_CACHE_MAX_MB", "256") or 256) * 1024 * 1024)
_RULE_CACHE_LOCK = threading.Lock()
# Fixed lookup-dataset base name (stable so dashboards can reference literally):
#   <prefix>_matches -> one row per matched YARA string
#   <prefix>_scans   -> scan-lifecycle rows (initiated/running/completed/cancelled/failed)
LOOKUP_DATASET_PREFIX = "yara_scanner"
SCANS_HEARTBEAT_SECS = float(os.environ.get("YARA_HEARTBEAT_SECS", "600") or 600)  # running-row cadence
# How many past scans' logs (+ their JSON summary) to keep on the endpoint. The old value (2)
# wiped diagnostics too aggressively under frequent scans; keep more by default, configurable.
LOG_KEEP_SCANS = int(os.environ.get("YARA_LOG_KEEP", "10") or 10)
CANCEL_POLL_SECS = float(os.environ.get("YARA_CANCEL_POLL_SECS", "5") or 5)        # cancel-flag watcher cadence
CANCEL_DRAIN_DEADLINE_SECS = float(os.environ.get("YARA_CANCEL_DEADLINE_SECS", "30") or 30)  # graceful cancel budget
CANCEL_STALE_TOLERANCE_SECS = 2.0  # mtime slack when judging a cancel flag stale (coarse-FS safety)
XDR_API_KEY = DEFAULT_XDR_API_KEY
XDR_API_ID = DEFAULT_XDR_API_ID
XDR_API_URL = DEFAULT_XDR_API_URL

# XDR public-API authentication mode.
#   "auto"     -> probe the tenant once (Advanced first, then Standard) and cache the winner
#   "advanced" -> per-request HMAC signature (x-xdr-nonce + x-xdr-timestamp + sha256(key+nonce+ts))
#   "standard" -> plain header (Authorization: <key> + x-xdr-auth-id)
# Advanced is the modern default for Cortex XDR/XSIAM API keys; Standard-only keys still work via auto.
XDR_AUTH_TYPE = (os.environ.get("XDR_AUTH_TYPE") or "auto").strip().lower()
_RESOLVED_AUTH_TYPE = None  # cache for "auto": resolved to "advanced" | "standard" on first use

YARA_RULE = r""""""


# Note: the cleanup script is now generated at runtime from config.alert_dir
# (CleanupManager._get_cleanup_script_content) instead of hardcoded base64 blobs,
# which previously drifted to the wrong directory (P2 fix).


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

    rule_pattern = re.compile(r'(?m)^\s*rule\s+\w+', re.IGNORECASE)
    rules_found = rule_pattern.findall(text)
    
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


def _lookup_backoff_delay(attempt_index, cap=6.0):
    """Full-jitter backoff for lookup add_data. Concurrent scanners hitting the same
    dataset all fail the clone-race together; correlated (exp*0.5..1) backoff makes them
    retry in step and keep colliding. Full jitter — a uniform pick in [0, ceiling] —
    decorrelates the herd so retries spread out and eventually thread through the race.
    Capped so many retries still fit the drain window."""
    ceiling = min(cap, BASE_BACKOFF_SECS * (2 ** attempt_index))
    return random.uniform(0.2, max(0.4, ceiling))


def _os_type() -> str:
    """Coarse OS family for dashboard segmentation (windows/linux/macos/other)."""
    s = platform.system()
    return {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(s, (s or "other").lower())


def _yara_version_tag() -> str:
    """Identity of the yara engine + platform for rule-cache keying. libyara (YARA_VERSION)
    drives the save/load serialization format; the binding version and platform tighten it so a
    3.11-Linux bundle and a 4.1-Windows bundle can never collide on one cache key."""
    return "%s/%s/%s/%s" % (
        getattr(yara, "__version__", "?"),
        getattr(yara, "YARA_VERSION", "?"),
        platform.system(),
        platform.machine(),
    )


def _dataset_shard_suffix(raw_label: str) -> str:
    """Turn an arbitrary shard label (usually a hostname) into a stable, XDR-legal dataset
    suffix. XDR dataset names must be lowercase [a-z0-9_] and start with a letter, so we
    slugify and cap the label, then append a short hash of the ORIGINAL so two hosts that
    slugify to the same string (or get truncated) still land in different datasets."""
    raw = str(raw_label or "unknown")
    slug = re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_")[:32] or "host"
    if not slug[0].isalpha():
        slug = "h_" + slug
    h = hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:6]
    return f"{slug}_{h}"


def _build_xdr_insert_alerts_url(api_url: str) -> str:
    """Build full Insert Parsed Alerts endpoint URL from a base or full URL."""
    base = (api_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith(XDR_INSERT_PARSED_ALERTS_PATH):
        return base
    return f"{base}{XDR_INSERT_PARSED_ALERTS_PATH}"


def _build_xdr_lookups_add_data_url(api_url: str) -> str:
    """Build the full Add Data to Lookup Dataset endpoint URL."""
    base = (api_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith(XDR_LOOKUPS_ADD_DATA_PATH):
        return base
    return f"{base}{XDR_LOOKUPS_ADD_DATA_PATH}"


def _build_xdr_get_datasets_url(api_url: str) -> str:
    """Build the full Get Datasets endpoint URL (used to check lookup-dataset existence)."""
    base = (api_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith(XDR_GET_DATASETS_PATH):
        return base
    return f"{base}{XDR_GET_DATASETS_PATH}"


def _build_xdr_add_dataset_url(api_url: str) -> str:
    """Build the full Add Dataset endpoint URL (used to create the lookup dataset)."""
    base = (api_url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith(XDR_ADD_DATASET_PATH):
        return base
    return f"{base}{XDR_ADD_DATASET_PATH}"


# ============================================================================
# XDR API AUTHENTICATION (centralized)
# ============================================================================

def _advanced_auth_headers():
    """Advanced (HMAC) auth headers. A fresh nonce+timestamp is generated per call,
    so callers MUST build headers per HTTP attempt (never reuse across retries).

    Uses os.urandom (not the `secrets` module): the Cortex agent's snippet/script
    sandbox enforces an import allowlist that rejects `secrets`.
    """
    nonce = os.urandom(32).hex()
    timestamp = str(int(time.time() * 1000))
    signature = hashlib.sha256((XDR_API_KEY + nonce + timestamp).encode("utf-8")).hexdigest()
    return {
        "x-xdr-timestamp": timestamp,
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(XDR_API_ID),
        "Authorization": signature,
        "Content-Type": "application/json",
    }


def _standard_auth_headers():
    """Standard auth headers (plain API key)."""
    return {
        "Authorization": XDR_API_KEY,
        "x-xdr-auth-id": str(XDR_API_ID),
        "Content-Type": "application/json",
    }


def _xdr_configured() -> bool:
    """True when a real (non-placeholder) XDR API URL is configured."""
    return bool(XDR_API_URL) and "replace_with" not in (XDR_API_URL or "")


def _probe_auth_type(log_manager=None):
    """Detect whether the tenant expects Advanced or Standard auth; cache the result.

    Probes get_datasets (a cheap authenticated no-op) with Advanced then Standard.
    Falls back to 'advanced' when the probe is inconclusive or the tenant is offline.
    """
    global _RESOLVED_AUTH_TYPE
    if _RESOLVED_AUTH_TYPE:
        return _RESOLVED_AUTH_TYPE

    url = _build_xdr_get_datasets_url(XDR_API_URL)
    if not url or not _xdr_configured():
        _RESOLVED_AUTH_TYPE = "advanced"
        return _RESOLVED_AUTH_TYPE

    for auth in ("advanced", "standard"):
        headers = _advanced_auth_headers() if auth == "advanced" else _standard_auth_headers()
        try:
            resp = requests.post(url, headers=headers, json={"request": {}}, timeout=DEFAULT_TIMEOUT_SECS)
        except Exception as e:  # noqa: BLE001 - network errors leave detection for next call
            if log_manager:
                log_manager.log_upload(f"XDR auth probe ({auth}) network error: {e}")
            return "advanced"  # transient; do not cache
        if 200 <= resp.status_code < 300:
            _RESOLVED_AUTH_TYPE = auth
            if log_manager:
                log_manager.log_upload(f"XDR auth type detected: {auth}")
            return auth

    _RESOLVED_AUTH_TYPE = "advanced"
    if log_manager:
        log_manager.log_upload("XDR auth probe inconclusive; defaulting to advanced")
    return _RESOLVED_AUTH_TYPE


def build_xdr_headers(log_manager=None):
    """Return XDR API request headers using the configured/detected auth type.

    Call this fresh for every HTTP attempt: Advanced auth embeds a per-request
    nonce+timestamp that must not be replayed across retries.
    """
    if XDR_AUTH_TYPE in ("advanced", "standard"):
        auth = XDR_AUTH_TYPE
    else:
        auth = _probe_auth_type(log_manager)
    return _advanced_auth_headers() if auth == "advanced" else _standard_auth_headers()


# ============================================================================
# CONFIG HELPERS (runtime options + tenant identity)
# ============================================================================

def _clamp_pct(value, default):
    """Coerce a percentage-like value into 1..100, falling back to default."""
    try:
        v = float(value) if value is not None else float(default)
    except (TypeError, ValueError):
        v = float(default)
    return max(1.0, min(100.0, v))


def _coerce_float(value, default):
    """Coerce to float, falling back to default; negatives clamped to 0."""
    try:
        v = float(value) if value is not None else float(default)
    except (TypeError, ValueError):
        v = float(default)
    return v if v >= 0 else 0.0


def _derive_tenant_id(api_url, override=""):
    """Best-effort tenant slug. Cortex hosts look like api-<tenant>.xdr.<region>...

    An explicit override always wins; otherwise parse the FQDN. Never fails —
    returns 'unknown' when nothing can be derived (labeling must not break a scan).
    """
    if override and str(override).strip():
        return str(override).strip()
    text = api_url or ""
    m = re.search(r"api-([^./]+)\.xdr\.", text)
    if m:
        return m.group(1)
    try:
        host = text.split("//")[-1].split("/")[0]
        first = host.split(".")[0]
        return first or "unknown"
    except Exception:
        return "unknown"


# Runtime options exposed through the compact `options` string parameter
# (key=value,key=value). Kept small on purpose: each is also a plain kwarg on
# main()/ScanConfig for standalone use.
_VALID_OPTION_KEYS = {
    "create_alerts", "write_dataset", "collect_files",
    "throttle_mode", "cpu_high_threshold", "cpu_critical_threshold",
    "max_pause_secs", "tenant_id", "lookup_shard",
}


def _parse_options_string(options):
    """Parse `key=value,key=value` into a dict of recognized options.

    Booleans/numbers are left as raw strings here; ScanConfig coerces them.
    Unknown keys raise ValueError so operator typos fail loudly instead of
    silently doing nothing.
    """
    parsed = {}
    if not options:
        return parsed
    text = _ensure_text(options).strip()
    if not text:
        return parsed
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise ValueError(f"Invalid option '{chunk}'. Expected key=value.")
        k, v = chunk.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        if k not in _VALID_OPTION_KEYS:
            raise ValueError(
                f"Unknown option '{k}'. Valid keys: {', '.join(sorted(_VALID_OPTION_KEYS))}"
            )
        parsed[k] = v
    return parsed


def _default_scanner_dir():
    """Platform default scanner working directory (matches ScanConfig)."""
    override = os.environ.get("YARA_SCANNER_DIR")
    if override and override.strip():
        return override.strip()
    if platform.system() == "Windows":
        return "C:\\yara_scanner"
    if platform.system() == "Darwin":
        return "/usr/local/yara_scanner"
    return "/opt/yara_scanner"


def _handle_cancel_request(tenant_id_override=""):
    """mode=cancel: drop a cooperative cancel flag for a running scan on this endpoint.

    Deliberately lightweight — does NOT initialize the full logging/scan machinery.
    Writes <scanner_dir>/control/cancel.flag and reports whether a scan appears to be
    running via the running.json liveness marker that an active scan refreshes.
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
                running_info = json.load(f)
            updated = float(running_info.get("updated_at", 0))
            # Fresh marker => a scan is (probably) alive. Generous window vs heartbeat.
            running = (time.time() - updated) < (SCANS_HEARTBEAT_SECS * 3 + 60)
    except Exception:
        running = False

    try:
        with open(flag_path, "w", encoding="utf-8") as f:
            json.dump({
                "requested_at_ms": int(time.time() * 1000),
                "source": "xdr_action",
                "tenant_id_override": tenant_id_override or "",
            }, f)
    except Exception as e:
        return f"Cancel failed: cannot write {flag_path}: {e}"

    return (
        f"Cancel signal delivered ({flag_path}) | scanner running: "
        f"{'yes' if running else 'no'} | scan_id={running_info.get('scan_id', 'n/a')}"
    )


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
    # External vars community rules reference in conditions. Declared here at compile time
    # AND populated per-file at match time (see scan_file) so `filename`/`filepath` rules
    # actually work — previously `filename` was undeclared (rules failed to compile) and
    # `filepath` was never set (always "", so those rules never matched).
    "filepath": "",
    "filename": "",
}

# Module -> regex that detects a rule *using* that module (e.g. `cuckoo.network...`). Single
# source of truth shared by _inject_missing_rule_imports (auto-import decision) and
# _rule_uses_unavailable_modules (skip-vs-fail decision) so "does this rule need module X" is
# answered identically in both places. A rule that references an UNAVAILABLE module can never
# compile on this agent, so it must be SKIPPED (module missing), not counted as a FAILED rule.
MODULE_USAGE_PATTERNS = OrderedDict([
    ("math", r"\bmath\."),
    ("elf", r"\belf\."),
    ("pe", r"\bpe\."),
    ("hash", r"\bhash\."),
    ("time", r"\btime\."),
    ("dotnet", r"\bdotnet\."),
    ("magic", r"\bmagic\."),
    ("cuckoo", r"\bcuckoo\."),
])


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
    Best-effort file creation time in ISO format with UTC timezone.
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


def _apply_light_process_priority(log_manager=None, throttle_mode="script"):
    """Best-effort process priority tuning so user activity wins on busy machines.

    throttle_mode:
      script/off -> baseline low priority (below-normal / nice 10 + ionice BE-7)
      os         -> idle-tier priority so the OS scheduler fully arbitrates and the
                    scanner never competes with real work (customer request: hand
                    resource control to the OS, bypassing script-side sleeps).
    All calls are best-effort; a failure here must never fail the scan.
    """
    details = {"throttle_mode": throttle_mode}
    os_mode = (throttle_mode == "os")
    try:
        process = psutil.Process()

        if platform.system() == "Windows":
            try:
                if os_mode:
                    process.nice(psutil.IDLE_PRIORITY_CLASS)
                    details["cpu_priority"] = "idle"
                    # Background mode also demotes I/O and memory priority (Win Vista+).
                    try:
                        process.nice(getattr(psutil, "PROCESS_MODE_BACKGROUND_BEGIN", 0x00100000))
                        details["background_mode"] = "begin"
                    except Exception as e:
                        details["background_mode_error"] = str(e)
                else:
                    process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                    details["cpu_priority"] = "below_normal"
            except Exception as e:
                details["cpu_priority_error"] = str(e)
        else:
            try:
                if os_mode:
                    target_nice = 19
                else:
                    current_nice = process.nice()
                    target_nice = max(int(current_nice), 10)
                process.nice(target_nice)
                details["cpu_priority"] = f"nice={target_nice}"
            except Exception as e:
                details["cpu_priority_error"] = str(e)

            if platform.system() == "Linux" and hasattr(process, "ionice"):
                try:
                    if os_mode:
                        process.ionice(psutil.IOPRIO_CLASS_IDLE)
                        details["io_priority"] = "idle"
                    else:
                        process.ionice(psutil.IOPRIO_CLASS_BE, 7)
                        details["io_priority"] = "best_effort:7"
                except Exception as e:
                    details["io_priority_error"] = str(e)

        if log_manager:
            log_manager.log_system("Applied process priority tuning", details)
    except Exception as e:
        if log_manager:
            log_manager.log_system(f"Could not apply process priority tuning: {e}")

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
    """Standardized log entry used for XDR alert uploads."""
    
    def __init__(self, log_type, hostname, os_info, ip_address, scan_id, message=None, level="INFO", data=None):
        current_time = time.time()
        
        self.type = log_type
        self.hostname = hostname
        self.os_info = os_info
        self.ipAddress = ip_address
        self.timestamp = current_time
        self.scan_id = scan_id
        self.timestamp_iso = datetime.datetime.fromtimestamp(current_time).isoformat()
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
    """Circuit breaker pattern for resilient XDR API uploads."""
    
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
        self.skipped_rules_count = 0  # rules skipped for unavailable modules (persisted to rule cache)
    
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
        """Get current statistics snapshot for reporting."""
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
    """Centralized log manager for file-based logging."""

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

        self.upload_stats = {
            'total_logs': 0,
            'by_type': {log_type.value: 0 for log_type in LogType}
        }
        self._stopped = False

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

    def _log(self, log_type, message, level="INFO", data=None):
        """Write log message to its dedicated file.

        Structured `data` (dicts passed by call sites) used to be accepted and silently
        dropped — it is now serialized onto the line as JSON so the context an operator
        actually needs (error types, failure reasons, counts) survives in the log. Capped
        so a stray large payload can't bloat the file.
        """
        if data is not None:
            try:
                blob = json.dumps(data, default=str, ensure_ascii=False, sort_keys=True)
            except Exception:
                blob = repr(data)
            if len(blob) > 4000:
                blob = blob[:4000] + "...(truncated)"
            message = f"{message} | data={blob}"
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

    def log_alert(self, message: str, data=None):
        """Log alert message."""
        self._log(LogType.ALERT, message, "INFO", data)

    def log_statistics(self, message: str, data=None):
        """Log statistics message."""
        self._log(LogType.STATISTICS, message, "INFO", data)

    def log_error(self, message: str, data=None):
        """Log error message."""
        self._log(LogType.ERROR, message, "ERROR", data)

    def log_performance(self, message: str, data=None):
        """Log performance message."""
        self._log(LogType.PERFORMANCE, message, "INFO", data)

    def log_upload(self, message: str, data=None):
        """Log upload message."""
        self._log(LogType.UPLOAD, message, "INFO", data)

    def log_system(self, message: str, data=None):
        """Log system message."""
        self._log(LogType.SYSTEM, message, "INFO", data)


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
        """Get current log generation statistics."""
        return self.upload_stats.copy()

    def log_final_summary(self):
        """Log comprehensive final summary."""
        summary_data = {
            'total_logs_generated': self.upload_stats['total_logs'],
            'logs_by_type': self.upload_stats['by_type'].copy(),
            'log_files_created': {log_type.value: self.log_files[log_type] for log_type in LogType}
        }

        message = f"Logging Summary | Total Logs: {self.upload_stats['total_logs']}"

        self.log_system(message, summary_data)

    def write_scan_summary(self, summary: dict):
        """Write a single machine-readable scan summary JSON for this run.

        The six per-category text logs are for humans; this one file is for tools — the skill,
        an Action Center follow-up, or the customer's own automation can read one JSON instead
        of grepping six logs. Written atomically so a reader never sees a half-written file.
        """
        path = os.path.join(self.config.logs_dir, f"scan_summary_{self.config.run_id}.json")
        record = {
            "schema": "yara_scan_summary/v1",
            "run_id": self.config.run_id,
            "scan_id": self.scan_id,
            "tenant_id": getattr(self.config, "tenant_id", ""),
            "hostname": self.hostname,
            "os_info": self.os_info,
            "ip_address": self.ip_address,
            "matches_dataset": getattr(self.config, "_matches_dataset", ""),
            "scans_dataset": getattr(self.config, "_scans_dataset", ""),
            "posture": getattr(self.config, "posture", ""),
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
    
    def __init__(self, config, log_manager):
        self.config = config
        self.log_manager = log_manager
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
        """Record a resource snapshot to the local performance log."""
        try:
            trends = self._calculate_resource_trends()

            enhanced_data = resource_data.copy()
            enhanced_data.update({
                'trends': trends,
                'alert_count_last_hour': len([a for a in self.alert_history
                                            if time.time() - a['timestamp'] < 3600]),
                'monitoring_duration_minutes': (time.time() - self.system_boot_time) / 60
            })

            self.log_manager.log_performance(
                f"System resources - CPU: {resource_data['process']['cpu_percent']:.1f}%, Memory: {resource_data['process']['memory_mb']:.1f}MB",
                enhanced_data
            )

        except Exception as e:
            self.log_manager.log_error(f"Failed to record resource data: {e}")

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
            self.log_manager.log_performance(
                f"Resource monitoring completed: {final_summary['data_points_collected']} snapshots, {final_summary['alerts_triggered']} alerts",
                final_summary
            )


# ============================================================================
# CONFIGURATION
# ============================================================================

class ScanConfig:
    """Configuration class for scan settings and environment setup."""

    def __init__(self, yarafile, scan_folder=None, alert_severity="low",
                 mode="scan", create_alerts=True, write_dataset=True,
                 collect_files=False, throttle_mode="script",
                 cpu_high_threshold=None, cpu_critical_threshold=None,
                 max_pause_secs=None, tenant_id="", lookup_shard=""):
        self.hostname, self.ip_addresses, self.os_info = get_system_info()
        # Lookup-dataset shard selector (see LOOKUP_DATASET_SHARD). Empty => module default
        # ("endpoint" = per-host datasets, which sidesteps the add_data concurrency race).
        self.lookup_shard = str(lookup_shard).strip() if lookup_shard else ""
        self.run_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        # Roadmap Feature: Caching is disabled by default
        self.use_cache = False
        self.light_profile = True
        parsed_alert_severity = _parse_alert_severity(alert_severity, "alert_severity")
        self.alert_severity = "low" if parsed_alert_severity is None else parsed_alert_severity

        # --- v2 runtime options (all default to preserve prior behavior, except
        #     collect_files which now defaults OFF per customer request) ---
        self.mode = (str(mode) if mode is not None else "scan").strip().lower() or "scan"
        if self.mode not in ("scan", "cancel"):
            raise ValueError(f"Invalid mode '{mode}'. Use scan or cancel.")
        _ca = _parse_bool_arg(create_alerts, "create_alerts")
        self.create_alerts = True if _ca is None else _ca
        _wd = _parse_bool_arg(write_dataset, "write_dataset")
        self.write_dataset = True if _wd is None else _wd
        _cf = _parse_bool_arg(collect_files, "collect_files")
        self.collect_files = False if _cf is None else _cf
        self.throttle_mode = (str(throttle_mode) if throttle_mode is not None else "script").strip().lower() or "script"
        if self.throttle_mode not in ("script", "os", "off"):
            raise ValueError(f"Invalid throttle_mode '{throttle_mode}'. Use script, os, or off.")
        # CPU thresholds/max-pause are applied in the throttle-config block below.
        self._opt_cpu_high = cpu_high_threshold
        self._opt_cpu_critical = cpu_critical_threshold
        self._opt_max_pause = max_pause_secs
        self._tenant_id_override = (str(tenant_id).strip() if tenant_id else "")
        # Posture summary string surfaced in logs and the final result line.
        self.posture = (
            f"alerts={'on' if self.create_alerts else 'off'} "
            f"dataset={'on' if self.write_dataset else 'off'} "
            f"files={'on' if self.collect_files else 'off'} "
            f"throttle={self.throttle_mode} mode={self.mode}"
        )
        self.scanner_dir = _default_scanner_dir()

        self.logs_dir = os.path.join(self.scanner_dir, "logs")
        self.control_dir = os.path.join(self.scanner_dir, "control")
        os.makedirs(self.scanner_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.control_dir, exist_ok=True)

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

        global XDR_API_KEY, XDR_API_ID, XDR_API_URL

        XDR_API_KEY = DEFAULT_XDR_API_KEY
        self.api_key_source = "default"

        XDR_API_ID = DEFAULT_XDR_API_ID
        self.api_id_source = "default"

        XDR_API_URL = DEFAULT_XDR_API_URL
        self.api_url_source = "default"

        # Detect un-configured credentials: the shipped script has "replace_with_*" placeholders
        # that the customer MUST replace with their real Advanced API key + tenant URL before
        # uploading. If they don't, every alert/dataset upload fails ("No scheme supplied") and a
        # perfect scan silently delivers nothing. Flag it here so run() can fail loud up front.
        self.creds_placeholder = any(
            "replace_with" in str(v).lower() or not str(v).strip()
            for v in (XDR_API_URL, XDR_API_KEY, XDR_API_ID)
        )

        # Tenant identity: explicit override wins, else derived from the API URL.
        self.tenant_id = _derive_tenant_id(XDR_API_URL, self._tenant_id_override)

        if self.creds_placeholder:
            self.error_logger.error_logger.error(
                "XDR API CREDENTIALS NOT SET — DEFAULT_XDR_API_KEY / DEFAULT_XDR_API_ID / "
                "DEFAULT_XDR_API_URL are still 'replace_with_*' placeholders. Alerts and lookup "
                "datasets CANNOT be delivered. Edit the three credential lines at the top of the "
                "script (real Advanced API key + https tenant URL) and re-upload."
            )

        self.error_logger.error_logger.info("XDR API Key: Using default embedded credential")
        self.error_logger.error_logger.info("XDR API ID: Using default embedded credential")
        self.error_logger.error_logger.info(f"XDR API URL: {XDR_API_URL}")
        self.error_logger.error_logger.info(f"Tenant ID: {self.tenant_id}")
        self.error_logger.error_logger.info(f"Runtime posture: {self.posture}")
        self.error_logger.error_logger.info(f"Default XDR alert severity: {self.alert_severity}")
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
        # scan_id must be unique per scan run, not per ruleset. Two hosts (or two
        # runs on one host) using the same rules previously collided on a single
        # rule-hash scan_id, which broke multi-host correlation in XDR. The hash
        # prefix is preserved (truncated to 12 chars) so the ruleset is still
        # identifiable from the scan_id alone.
        self.rule_hash = yara_hash
        self.scan_id = f"{self.hostname}_{self.run_id}_yara_{yara_hash[:12]}"
        self.error_logger.error_logger.info(f"Scan ID: {self.scan_id} (rule hash: {yara_hash[:12]}...)")

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
        # Throttling is active unless the operator hands resource control to the OS
        # (throttle_mode="os") or disables it outright (throttle_mode="off").
        self.light_throttle_enabled = (self.throttle_mode == "script")
        self.throttle_check_interval_secs = float(os.getenv("YARA_LIGHT_THROTTLE_CHECK_SECS", "0.5") or 0.5)
        # CPU thresholds: script-parameter override wins over env default.
        self.high_cpu_threshold = _clamp_pct(self._opt_cpu_high, os.getenv("YARA_LIGHT_HIGH_CPU", "80") or 80)
        self.critical_cpu_threshold = _clamp_pct(self._opt_cpu_critical, os.getenv("YARA_LIGHT_CRITICAL_CPU", "90") or 90)
        if self.critical_cpu_threshold <= self.high_cpu_threshold:
            self.critical_cpu_threshold = min(100.0, self.high_cpu_threshold + 5.0)
            self.error_logger.error_logger.warning(
                "cpu_critical_threshold <= cpu_high_threshold; bumped critical to "
                f"{self.critical_cpu_threshold:.0f}"
            )
        # Resume hysteresis: workers resume once CPU falls this far below the high mark.
        self.resume_margin = float(os.getenv("YARA_LIGHT_RESUME_MARGIN", "10") or 10)
        # Cap on one continuous CPU pause (0 = unbounded). Param override wins.
        self.max_pause_secs = _coerce_float(self._opt_max_pause, os.getenv("YARA_MAX_PAUSE_SECS", "300") or 300)
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
        )
        # Always-scan carve-outs (checked BEFORE skip logic): browser caches/profiles
        # are common malware staging/persistence areas, so they are scanned even when a
        # broader skip fragment/dir would otherwise exclude them. On Windows/Linux the
        # browser-cache skip fragments were removed above; this list surgically re-opens
        # browser caches on macOS where the broad "/library/caches/" (and the mac skip
        # dirs) would still bypass them. Safari is best-effort under TCC/Full Disk Access.
        self.force_scan_fragments = (
            "/library/caches/google/chrome/",
            "/library/caches/chromium/",
            "/library/caches/microsoft edge/",
            "/library/caches/firefox/",
            "/library/caches/com.apple.safari/",
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
    """Real-time YARA match uploader using Cortex XDR Insert Parsed Alerts API."""
    
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
            'failed_uploads': 0
        }
        
        # create_alerts gates the Insert Parsed Alerts channel (XDR alerts -> incidents).
        if UPLOAD_RESULTS and getattr(config, "create_alerts", True):
            self._start_upload_thread()
        elif self.log_manager:
            self.log_manager.log_upload("Parsed-alerts upload disabled (create_alerts=false)")

    def _start_upload_thread(self):
        """Start background upload thread."""
        if not XDR_API_URL:
            if self.log_manager:
                self.log_manager.log_upload("XDR_API_URL not configured - real-time match upload disabled")
            return
            
        if self.log_manager:
            self.log_manager.log_upload("Starting real-time upload thread...")
            
        self.upload_thread = threading.Thread(target=self._upload_worker, daemon=True)
        self.upload_thread.start()
        
        if self.log_manager:
            self.log_manager.log_upload("Real-time upload thread started successfully")

    def _upload_worker(self):
        """Background worker for uploading results."""
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

    def _build_xdr_parsed_alert(self, standard_log: StandardLogEntry):
        """Map internal YARA match data to XDR Insert Parsed Alerts schema."""
        data = getattr(standard_log, "data", {}) or {}

        event_timestamp_ms = int(getattr(standard_log, "timestamp", time.time()) * 1000)
        rule_name = data.get("rule", "unknown_rule")
        hostname = getattr(standard_log, "hostname", "UnknownHost")
        # Alert identity = the FINDING (rule + file + offset), NOT the scan time. XDR aggregates
        # alerts that share an alert_name, so:
        #   - putting the timestamp in the name made every re-scan mint NEW alerts (alert flood)
        #     AND collapsed distinct matches that shared a millisecond into one — the opposite of
        #     what we want.
        #   - a stable per-finding name makes alerts 1:1 with distinct matches within a scan, and
        #     idempotent across repeated scans of the same location (XDR updates the existing
        #     alert instead of piling on duplicates). event_timestamp still carries the scan time.
        _full_path = str(data.get("filename", "") or data.get("file", ""))
        match_file = os.path.basename(_full_path)
        match_offset = data.get("offset", "")
        # Tag the identity with a stable hash of the FULL path so two distinct files that share a
        # basename (e.g. per-user copies of one dropper at ...\alice\svchost.exe and ...\bob\svchost.exe)
        # don't collapse into a single alert. basename alone loses the path; file_sha256 can't separate
        # byte-identical copies at different locations. Same path -> same tag keeps re-scans idempotent.
        _path_tag = hashlib.sha1(_full_path.encode("utf-8", "replace")).hexdigest()[:8] if _full_path else "nopath"
        alert_name = f"YARA Match: {rule_name} | {match_file}@{match_offset} (#{_path_tag}) | Host: {hostname}"

        severity_map = {
            "critical": "High",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Low",
        }
        default_level = getattr(self.config, "alert_severity", "low")
        severity = severity_map.get(str(data.get("threat_level", default_level)).lower(), "Low")

        host_ipv4 = "127.0.0.1"
        for ip in self.config.ip_addresses or []:
            if "." in ip and not ip.startswith("127."):
                host_ipv4 = ip
                break

        alert_description = {
            "source": "yara_scanner",
            "tenant_id": getattr(self.config, "tenant_id", "unknown"),
            "scan_id": standard_log.scan_id,
            "hostname": standard_log.hostname,
            "os_info": standard_log.os_info,
            "ip_address": standard_log.ipAddress,
            "message": getattr(standard_log, "message", ""),
            "network_fields_are_placeholders": True,
            "match_data": data,
        }

        alert = {
            "product": "YARA Scanner",
            "vendor": "Custom",
            "local_ip": host_ipv4,
            "local_port": 65535,
            "remote_ip": "127.0.0.1",
            "remote_port": 65535,
            "event_timestamp": event_timestamp_ms,
            "severity": severity,
            "alert_name": alert_name,
            "alert_description": json.dumps(alert_description, ensure_ascii=False, default=str),
            "action_status": "Reported",
        }
        return {"request_data": {"alerts": [alert]}}

    def _upload_standard_result(self, standard_log: StandardLogEntry):
        """Upload YARA match with bounded retries."""
        payload = self._build_xdr_parsed_alert(standard_log)
        endpoint = _build_xdr_insert_alerts_url(XDR_API_URL)

        attempt = 0
        while attempt < MAX_RETRIES_PER_ITEM:
            attempt += 1
            try:
                resp = requests.post(
                    url=endpoint,
                    headers=build_xdr_headers(self.log_manager),
                    json=payload,
                    timeout=DEFAULT_TIMEOUT_SECS,
                )
                if 200 <= resp.status_code < 300:
                    api_reply_ok = True
                    try:
                        parsed = resp.json()
                        if isinstance(parsed, bool):
                            api_reply_ok = parsed
                    except Exception:
                        pass
                    if not api_reply_ok:
                        self.upload_stats['failed_uploads'] += 1
                        if self.log_manager:
                            self.log_manager.log_error("XDR Insert Parsed Alerts returned false")
                        return False
                    self.upload_stats['successful_uploads'] += 1
                    if self.log_manager:
                        self.log_manager.log_upload(f"YARA match upload successful (HTTP {resp.status_code})")
                    return True

                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    delay = _exp_backoff_delay(attempt)
                    if self.log_manager:
                        self.log_manager.log_upload(
                            f"Upload failed (HTTP {resp.status_code}). Body: {resp.text[:500]}. "
                            f"Retrying in {delay:.1f}s (attempt {attempt}/{MAX_RETRIES_PER_ITEM})."
                        )
                    time.sleep(delay)
                    continue

                self.upload_stats['failed_uploads'] += 1
                if self.log_manager:
                    self.log_manager.log_error(f"YARA match upload failed (HTTP {resp.status_code}): {resp.text}")
                return False

            except (requests.Timeout, requests.ConnectionError) as e:
                delay = _exp_backoff_delay(attempt)
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"Network error uploading result: {e}. Retrying in {delay:.1f}s "
                        f"(attempt {attempt}/{MAX_RETRIES_PER_ITEM})."
                    )
                time.sleep(delay)

            except Exception as e:
                self.upload_stats['failed_uploads'] += 1
                if self.log_manager:
                    self.log_manager.log_error(f"YARA match upload unexpected error: {e}")
                return False

        self.upload_stats['failed_uploads'] += 1
        if self.log_manager:
            self.log_manager.log_error("Max retries reached for payload. Abandoning.")
        return False

    def stop(self, wait=True):
        """Stop uploader thread with timeout."""
        try:
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
        except Exception as e:
            if self.log_manager:
                self.log_manager.log_error(f"Error stopping results uploader: {e}")

    def add_match(self, filename, rule, match_data, file_sha256=None, file_creation_time=None):
        """Add YARA match and queue for upload."""
        match_count = 0
        # Resolve per-file context once (not per matched string).
        try:
            _file_size = int(os.path.getsize(filename))
        except Exception:
            _file_size = -1
        _scan_folder = str(getattr(self.config, "scan_folder", None) or "system")
        for string_id, offset, string_data in match_data:
            # Capture the matched BYTE length BEFORE rendering. _render_match_data decodes wide
            # matches to UTF-16 text (half the bytes) and binary matches to hex (double), so
            # len() of the rendered string is not a consistent size. len() of the raw matched
            # data is the byte length (capped by yara's max_match_data, ~512).
            _matched_len = len(string_data) if string_data is not None else 0
            string_data = _render_match_data(string_data)

            result = {
                "hostname": self.hostname,
                "os_info": self.os_info,
                "ipAddress": self.ip_address,
                "dateOfScan": self.date_of_scan,
                "filename": filename,
                "rule": rule,
                "string": string_data,
                "offset": str(offset),
                "match": string_id,
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
                        message=f"YARA match: rule '{rule}' in {filename}",
                        level="INFO",
                        data={
                            'filename': filename,
                            'rule': rule,
                            'string': string_data,
                            'offset': str(offset),
                            'match': string_id,
                            'dateOfScan': self.date_of_scan,
                            'file_sha256': file_sha256,
                            'file_creation_time': file_creation_time
                        }
                    )
                    self.upload_queue.put(standard_log, timeout=1.0)
                    if self.log_manager:
                        self.log_manager.log_upload(f"Queued match for upload: rule='{rule}', offset={offset}")
                except Exception:
                    if self.log_manager:
                        self.log_manager.log_upload("Upload queue full - skipping real-time upload for match")

            lookup_uploader = getattr(self, "lookup_uploader", None)
            if lookup_uploader is not None:
                severity_map = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low", "info": "Low"}
                default_level = getattr(self.config, "alert_severity", "low")
                severity = severity_map.get(str(default_level).lower(), "Low")
                lookup_record = {
                    "tenant_id": getattr(self.config, "tenant_id", "unknown"),
                    "scan_id": self.scan_id,
                    "run_id": getattr(self.config, "run_id", "") or "",
                    "scan_date": (getattr(self.config, "run_id", "") or "").split("_", 1)[0],
                    "hostname": self.hostname,
                    "os_info": self.os_info,
                    "os_type": _os_type(),
                    "ip_address": self.ip_address,
                    "rule": rule,
                    "filename": filename,
                    "file_size": _file_size,
                    "file_sha256": file_sha256 or "",
                    "file_creation_time": file_creation_time or "",
                    "scan_folder": _scan_folder,
                    "match": string_id,
                    "offset": str(offset),
                    "matched_length": _matched_len,
                    "string": string_data,
                    "severity": severity,
                    "event_timestamp_ms": int(time.time() * 1000),
                    "date_of_scan": self.date_of_scan,
                }
                lookup_uploader.add(lookup_record)

        if self.log_manager:
            self.log_manager.log_upload(f"Added {match_count} matches for rule '{rule}' in file: {filename}")

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


class LookupDatasetUploader:
    """Append YARA matches to a Cortex XDR Lookup Dataset (one row per matched string).

    Dataset name is derived from the run_id, e.g. ``yara_matches_20260518_143015_123456``.
    The dataset is created implicitly on the first ``add_data`` POST, so no separate
    create step is required. An upfront ``get_datasets`` call is made to log whether
    we are creating fresh or appending to an existing dataset.

    Matches are batched (LOOKUP_DATASET_BATCH_SIZE rows per POST) to stay under XDR's
    ~1000 entries / 10s rate limit AND to minimise the number of POSTs (each POST is one
    chance to hit the server-side add_data clone-table race). A timer flushes any partial
    batch after LOOKUP_DATASET_FLUSH_SECS idle; that interval is deliberately long so short
    scans emit a single end-of-scan POST per dataset instead of a trickle. Each POST is also
    preceded by a small random delay (LOOKUP_WRITE_JITTER_SECS) to decorrelate the fleet.
    """

    def __init__(self, config, log_manager=None):
        self.config = config
        self.log_manager = log_manager
        self.tenant_id = getattr(config, "tenant_id", "unknown")
        # scan_date (YYYYMMDD) bounds dataset growth via targeted remove_data pruning,
        # replacing the old daily-rotating dataset NAME (which dashboards can't follow).
        self.scan_date = (config.run_id.split("_", 1)[0] if getattr(config, "run_id", "") else
                          datetime.datetime.now().strftime("%Y%m%d"))
        # Per-writer dataset sharding — the fix for the add_data concurrency limitation.
        # shard = "endpoint" (default) gives each host its own dataset so no two writers ever
        # touch the same one; dashboards fan in with `dataset = yara_scanner_matches_*`.
        shard_cfg = str(getattr(config, "lookup_shard", "") or LOOKUP_DATASET_SHARD).strip().lower()
        if shard_cfg in ("none", "shared", "off", ""):
            self.dataset_shard = ""
        elif shard_cfg in ("endpoint", "host", "hostname", "auto"):
            self.dataset_shard = _dataset_shard_suffix(getattr(config, "hostname", "") or "host")
        else:
            self.dataset_shard = _dataset_shard_suffix(shard_cfg)
        _suffix = f"_{self.dataset_shard}" if self.dataset_shard else ""
        _ver = f"_v{LOOKUP_SCHEMA_VERSION}"  # schema-version tag; bump when the row shape changes
        self.matches_dataset = f"{LOOKUP_DATASET_PREFIX}_matches{_ver}{_suffix}"
        self.scans_dataset = f"{LOOKUP_DATASET_PREFIX}_scans{_ver}{_suffix}"
        # Surface the resolved (sharded) dataset names so the scan-summary JSON and logs can
        # tell the operator exactly where this scan's rows landed.
        try:
            config._matches_dataset = self.matches_dataset
            config._scans_dataset = self.scans_dataset
        except Exception:
            pass
        self.queue = Queue()
        self.upload_thread = None
        self.stop_flag = False
        self.batch_size = LOOKUP_DATASET_BATCH_SIZE
        self.flush_interval = LOOKUP_DATASET_FLUSH_SECS
        # Guards upload_stats when the final drain flushes the two datasets concurrently.
        self._stats_lock = threading.Lock()
        self.upload_stats = {
            "queued": 0,
            "batches_sent": 0,
            "records_added": 0,
            "records_updated": 0,
            "records_skipped": 0,
            "send_failures": 0,
            "dropped": 0,
        }

        # Matches schema — must match keys produced by ResultsUploader.add_match.
        # XDR add_dataset supports: text, number, datetime, bool.
        self.matches_schema = {
            "tenant_id": "text",
            "scan_id": "text",
            "run_id": "text",
            "scan_date": "text",
            "hostname": "text",
            "os_info": "text",
            "os_type": "text",          # coarse family (windows/linux/macos) for dashboard segmentation
            "ip_address": "text",
            "rule": "text",
            "filename": "text",
            "file_size": "number",      # size of the matched file in bytes
            "file_sha256": "text",
            "file_creation_time": "text",
            "scan_folder": "text",      # the target that was scanned (context for the hit)
            "match": "text",
            "offset": "text",
            "matched_length": "number", # length of the matched string data
            "string": "text",
            "severity": "text",
            "event_timestamp_ms": "number",
            "date_of_scan": "text",
        }
        # Scans lifecycle schema — one row per lifecycle transition/heartbeat.
        self.scans_schema = {
            "tenant_id": "text",
            "scan_id": "text",
            "run_id": "text",
            "scan_date": "text",
            "hostname": "text",
            "os_info": "text",
            "os_type": "text",          # coarse family (windows/linux/macos) for fleet segmentation
            "ip_address": "text",
            "status": "text",
            "scan_folder": "text",      # what was targeted (full-system vs scoped folder)
            "files_scanned": "number",
            "files_skipped": "number",
            "detections": "number",
            "valid_rules": "number",
            "failed_rules": "number",
            "scan_rate_fps": "number",
            "elapsed_secs": "number",
            "total_paused_secs": "number",
            "throttle_mode": "text",
            "posture": "text",
            "event_timestamp_ms": "number",
            "message": "text",
        }

        if UPLOAD_RESULTS and getattr(config, "write_dataset", True) and self._xdr_configured():
            self._ensure_datasets()
            self._start_thread()
        elif self.log_manager:
            self.log_manager.log_upload(
                "Lookup dataset uploads disabled (write_dataset=false, UPLOAD_RESULTS off, or XDR URL not configured)"
            )

    def _xdr_configured(self) -> bool:
        return bool(XDR_API_URL) and "replace_with" not in (XDR_API_URL or "")

    def _ensure_datasets(self):
        """Ensure both the matches and scans lookup datasets exist."""
        self._ensure_one(self.matches_dataset, self.matches_schema)
        self._ensure_one(self.scans_dataset, self.scans_schema)

    def _ensure_one(self, dataset_name, dataset_schema):
        """Probe get_datasets; create the dataset via add_dataset if it does not exist yet.

        XDR's add_data endpoint returns HTTP 400 "Dataset not found" when the lookup
        dataset hasn't been created, so creation is a hard prerequisite — not implicit.
        """
        found = False
        try:
            resp = requests.post(
                _build_xdr_get_datasets_url(XDR_API_URL),
                headers=build_xdr_headers(self.log_manager),
                json={"request": {}},
                timeout=DEFAULT_TIMEOUT_SECS,
            )
            if 200 <= resp.status_code < 300:
                try:
                    body = resp.json()
                    datasets = body.get("reply", body) if isinstance(body, dict) else body
                    if isinstance(datasets, dict):
                        datasets = datasets.get("data", []) or datasets.get("datasets", []) or []
                    # Docs say dataset_name; XDR actually returns "Dataset Name". Accept both.
                    found = any(
                        isinstance(d, dict)
                        and dataset_name in (d.get("dataset_name"), d.get("Dataset Name"))
                        for d in (datasets or [])
                    )
                except Exception as parse_err:
                    if self.log_manager:
                        self.log_manager.log_upload(
                            f"Could not parse get_datasets response: {parse_err}; "
                            f"will attempt add_dataset anyway."
                        )
            else:
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"get_datasets probe failed (HTTP {resp.status_code}): {resp.text[:200]}; "
                        f"will attempt add_dataset anyway."
                    )
        except Exception as e:
            if self.log_manager:
                self.log_manager.log_upload(
                    f"get_datasets probe error: {e}; will attempt add_dataset anyway."
                )

        if found:
            if self.log_manager:
                self.log_manager.log_upload(
                    f"Lookup dataset '{dataset_name}' already exists - will append rows"
                )
            return

        # Create
        try:
            resp = requests.post(
                _build_xdr_add_dataset_url(XDR_API_URL),
                headers=build_xdr_headers(self.log_manager),
                json={
                    "request": {
                        "dataset_name": dataset_name,
                        "dataset_type": "lookup",
                        "dataset_schema": dataset_schema,
                    }
                },
                timeout=DEFAULT_TIMEOUT_SECS,
            )
            if 200 <= resp.status_code < 300:
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"Lookup dataset '{dataset_name}' created "
                        f"(schema fields: {len(dataset_schema)})"
                    )
                return
            # XDR returns HTTP 500 with err_extra "Dataset X already exists" when the
            # dataset is in fact already there (often when our get_datasets probe
            # missed it for any reason). Treat that as success, not error.
            already_exists = False
            try:
                body = resp.json()
                reply = body.get("reply", body) if isinstance(body, dict) else {}
                err_extra = (reply.get("err_extra") or "") if isinstance(reply, dict) else ""
                if "already exists" in err_extra.lower():
                    already_exists = True
            except Exception:
                pass
            if already_exists:
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"Lookup dataset '{dataset_name}' already exists "
                        f"(reported via add_dataset 500) - will append rows"
                    )
                return
            if self.log_manager:
                self.log_manager.log_error(
                    f"Lookup dataset create failed (HTTP {resp.status_code}): {resp.text[:500]}. "
                    f"Subsequent add_data calls will likely fail with 'Dataset not found'."
                )
        except Exception as e:
            if self.log_manager:
                self.log_manager.log_error(f"Lookup dataset create error: {e}")

    def _start_thread(self):
        if self.log_manager:
            self.log_manager.log_upload(
                f"Lookup dataset upload thread starting (datasets: {self.matches_dataset}, "
                f"{self.scans_dataset}; batch_size: {self.batch_size})"
            )
        self.upload_thread = threading.Thread(target=self._worker, daemon=True)
        self.upload_thread.start()

    def add(self, record: dict):
        """Queue one match record for the matches dataset. Non-blocking."""
        self._enqueue(self.matches_dataset, record)

    def add_scan_row(self, record: dict):
        """Queue one scan-lifecycle record for the scans dataset. Non-blocking."""
        self._enqueue(self.scans_dataset, record)

    def _enqueue(self, target, record):
        # _enqueue runs on the scan-worker threads (via add/add_scan_row), so guard the counters
        # with the same _stats_lock the drain uses — bare += from N threads loses updates.
        if not self.upload_thread or not self.upload_thread.is_alive():
            # Worker never started or died — count and log once so dropped rows
            # (including the terminal lifecycle row) are diagnosable, not silent.
            with self._stats_lock:
                self.upload_stats["dropped"] = self.upload_stats.get("dropped", 0) + 1
            if self.log_manager and not getattr(self, "_drop_logged", False):
                self._drop_logged = True
                self.log_manager.log_error(
                    f"Lookup uploader thread not alive - dropping rows for {target} "
                    f"(further drops suppressed)"
                )
            return
        try:
            self.queue.put((target, record), timeout=1.0)
            with self._stats_lock:
                self.upload_stats["queued"] += 1
        except Exception:
            with self._stats_lock:
                self.upload_stats["dropped"] = self.upload_stats.get("dropped", 0) + 1
            if self.log_manager:
                self.log_manager.log_error("Lookup dataset queue full - dropping record")

    def _worker(self):
        if self.log_manager:
            self.log_manager.log_upload("Lookup dataset worker started")
        batches = defaultdict(list)  # target dataset -> pending rows
        last_flush = {}              # per-target: when the current batch started accumulating

        def flush_target(target):
            if batches[target]:
                self._send_batch(target, batches[target])
                batches[target] = []
                last_flush.pop(target, None)

        while True:
            try:
                item = self.queue.get(timeout=1.0)
                if item is None:
                    break
                target, rec = item
                if not batches[target]:
                    last_flush[target] = time.time()  # anchor this batch's flush timer
                batches[target].append(rec)
                if len(batches[target]) >= self.batch_size:
                    flush_target(target)
            except Empty:
                # Each dataset flushes on ITS OWN timer, so a busy matches stream cannot
                # starve the low-volume scans heartbeat (per-target last_flush).
                now = time.time()
                for target in list(batches.keys()):
                    if batches[target] and (now - last_flush.get(target, now)) >= self.flush_interval:
                        flush_target(target)
                if self.stop_flag and not any(batches.values()):
                    break
                continue
            except Exception as e:
                # Never let an unexpected error kill the uploader thread — that would
                # silently drop every subsequent row (matches + terminal lifecycle row).
                if self.log_manager:
                    self.log_manager.log_error(f"Lookup worker loop error (continuing): {e}")
                continue

        # Final drain: the matches and scans datasets are DIFFERENT datasets, so flushing them
        # concurrently can't trigger the same-dataset race — and since each add_data POST is slow
        # (~10s server-side), overlapping them roughly halves the shutdown drain instead of paying
        # ~10s + ~10s back to back.
        pending = [t for t in list(batches.keys()) if batches[t]]
        if len(pending) <= 1:
            for target in pending:
                flush_target(target)
        else:
            drain_threads = []
            for target in pending:
                th = threading.Thread(target=flush_target, args=(target,), daemon=True)
                th.start()
                drain_threads.append(th)
            for th in drain_threads:
                th.join(timeout=LOOKUP_DRAIN_TIMEOUT)
        if self.log_manager:
            self.log_manager.log_upload(
                f"Lookup dataset worker stopped "
                f"(batches={self.upload_stats['batches_sent']}, "
                f"added={self.upload_stats['records_added']}, "
                f"updated={self.upload_stats['records_updated']}, "
                f"skipped={self.upload_stats['records_skipped']}, "
                f"failures={self.upload_stats['send_failures']})"
            )

    def _send_batch(self, target, batch):
        if not batch:
            return
        payload = {
            "request": {
                "dataset_name": target,
                "data": batch,
            }
        }
        url = _build_xdr_lookups_add_data_url(XDR_API_URL)

        # Decorrelate the fleet burst: many endpoints POST to the SAME dataset at Job start (and
        # again as they finish). A small random pre-write delay spreads those synchronized writes
        # across a window so far fewer collide on the server-side per-second clone table. This is
        # the single biggest lever against the add_data race; retries only mop up the remainder.
        if LOOKUP_WRITE_JITTER_SECS > 0:
            time.sleep(random.uniform(0, LOOKUP_WRITE_JITTER_SECS))

        # Wall-clock deadline so this batch can't out-live the drain join budget. Without it, a
        # hung add_data endpoint (every POST blocking to the read timeout) makes 6 retries take
        # ~6*read_timeout, which exceeds LOOKUP_DRAIN_TIMEOUT; the daemon drain thread is then
        # killed mid-POST at process exit and the batch is lost SILENTLY (counted neither sent nor
        # failed). Refusing an attempt that can't finish in time lets the loop fall through to the
        # accounted send_failures + "rows lost" path BEFORE the join fires — visible, not silent.
        _read_to = LOOKUP_POST_TIMEOUT[1] if isinstance(LOOKUP_POST_TIMEOUT, (tuple, list)) else LOOKUP_POST_TIMEOUT
        _deadline = time.monotonic() + max(1.0, LOOKUP_DRAIN_TIMEOUT - 20)

        attempt = 0
        while attempt < LOOKUP_ADD_DATA_MAX_RETRIES:
            # `attempt > 0` guarantees at least ONE POST regardless of how the drain/read knobs are
            # tuned (a healthy endpoint then succeeds); the deadline only bounds the RETRIES so the
            # drain still exits within its join budget.
            if attempt > 0 and time.monotonic() + _read_to > _deadline:
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"Lookup batch deadline reached ({len(batch)} rows) after {attempt} attempts; "
                        f"stopping retries so the drain exits within budget."
                    )
                break
            attempt += 1
            try:
                resp = requests.post(url, headers=build_xdr_headers(self.log_manager), json=payload, timeout=LOOKUP_POST_TIMEOUT)
                if 200 <= resp.status_code < 300:
                    try:
                        body = resp.json()
                        result = body.get("reply", body) if isinstance(body, dict) else {}
                        # XDR returns field names with spaces ("rows added") in practice,
                        # while the API docs show "added" / "updated" / "skipped". Accept both.
                        added = int(result.get("rows added", result.get("added", 0)) or 0)
                        updated = int(result.get("rows updated", result.get("updated", 0)) or 0)
                        skipped = int(result.get("rows skipped", result.get("skipped", 0)) or 0)
                    except Exception:
                        added = updated = skipped = 0
                    with self._stats_lock:
                        self.upload_stats["batches_sent"] += 1
                        self.upload_stats["records_added"] += added
                        self.upload_stats["records_updated"] += updated
                        self.upload_stats["records_skipped"] += skipped
                    if self.log_manager:
                        self.log_manager.log_upload(
                            f"Lookup batch ok ({len(batch)} rows): added={added}, "
                            f"updated={updated}, skipped={skipped}"
                        )
                    return

                if resp.status_code in (408, 429, 500, 502, 503, 504):
                    delay = _lookup_backoff_delay(attempt)  # full-jitter: decorrelate the concurrent herd
                    if self.log_manager:
                        self.log_manager.log_upload(
                            f"Lookup batch failed (HTTP {resp.status_code}). Body: {resp.text[:500]}. "
                            f"Retry {attempt}/{LOOKUP_ADD_DATA_MAX_RETRIES} in {delay:.1f}s."
                        )
                    time.sleep(delay)
                    continue

                with self._stats_lock:
                    self.upload_stats["send_failures"] += 1
                if self.log_manager:
                    self.log_manager.log_error(
                        f"Lookup batch failed (HTTP {resp.status_code}): {resp.text[:500]}"
                    )
                return

            except (requests.Timeout, requests.ConnectionError) as e:
                delay = _lookup_backoff_delay(attempt)
                if self.log_manager:
                    self.log_manager.log_upload(
                        f"Lookup batch network error: {e}. Retry {attempt}/{LOOKUP_ADD_DATA_MAX_RETRIES} in {delay:.1f}s."
                    )
                time.sleep(delay)
            except Exception as e:
                with self._stats_lock:
                    self.upload_stats["send_failures"] += 1
                if self.log_manager:
                    self.log_manager.log_error(f"Lookup batch unexpected error: {e}")
                return

        with self._stats_lock:
            self.upload_stats["send_failures"] += 1
        if self.log_manager:
            self.log_manager.log_error(
                f"Lookup batch abandoned after {attempt} attempt(s) ({len(batch)} rows lost)"
            )

    def stop(self, wait=True):
        """Signal the worker to drain remaining batches and exit."""
        try:
            self.stop_flag = True
            try:
                self.queue.put(None, timeout=0.5)
            except Exception:
                pass
            if wait and self.upload_thread and self.upload_thread.is_alive():
                # Longer than the generic thread timeout: the final batch(es) may need the
                # full retry budget to thread through the add_data clone race under concurrency.
                self.upload_thread.join(timeout=LOOKUP_DRAIN_TIMEOUT)
                if self.upload_thread.is_alive() and self.log_manager:
                    self.log_manager.log_upload(
                        f"Lookup uploader thread did not stop within {LOOKUP_DRAIN_TIMEOUT}s"
                    )
        except Exception as e:
            if self.log_manager:
                self.log_manager.log_error(f"Error stopping lookup uploader: {e}")

    def get_upload_stats(self):
        return self.upload_stats.copy()


class ScanStatusUploader:
    """Periodic scan status uploader."""
    
    def __init__(self, config):
        self.config = config
        self.hostname = config.hostname
        self.os_info = config.os_info
        self.ip_address = config.ip_addresses[0] if config.ip_addresses else "Unknown"
        self.scan_id = config.scan_id
        self.scan_start_time = datetime.datetime.now()
        self.last_status_upload = time.time()
        self.status_upload_interval = 60
        self.scan_id = f"{self.hostname}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.scan_status = "starting"
        
    def upload_scan_status(self, scanner_stats=None):
        """Upload current scan status to XDR (disabled for match-only mode)."""
        if not UPLOAD_RESULTS or not UPLOAD_NON_MATCH_DATA or not XDR_API_URL:
            return
        
        current_time = datetime.datetime.now()
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
            
            response = requests.post(
                url=_build_xdr_insert_alerts_url(XDR_API_URL),
                headers=build_xdr_headers(),
                json=standard_log.to_dict(),
                timeout=10
            )
            
            if response.status_code == 200:
                logging.info("✓ Scan status uploaded successfully")
            else:
                logging.warning(f"⚠ Scan status upload failed: HTTP {response.status_code}")
                
        except Exception as e:
            logging.warning(f"⚠ Scan status upload error: {str(e)}")
    
    def set_status(self, status):
        """Update scan status."""
        self.scan_status = status
        logging.info(f"Scan status changed to: {status}")


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

        With collect_files=false (default), the zip is metadata-only: the matched
        files themselves are NOT copied, but file_mapping.txt (paths + SHA256) and
        the per-rule alert texts still let a responder locate and fetch files by
        path/hash manually.
        """
        copy_files = getattr(self.config, "collect_files", False)
        with zipfile.ZipFile(
            self.config.evidence_zip, "w", zipfile.ZIP_DEFLATED
        ) as zip_file:
            if copy_files:
                for file_path, file_hash in self.file_hashes.items():
                    try:
                        zip_file.write(file_path, f"matched_files/{file_hash}")
                    except Exception as e:
                        logging.error(f"Error adding file to zip {file_path}: {e}")
            else:
                logging.info("Evidence: collect_files=false - packaging metadata only (no matched file copies)")

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
        """Extract scan run_id from a standardized log or summary filename."""
        match = re.search(r'_(\d{8}_\d{6}_\d{6})\.(?:log|json)$', filename)
        return match.group(1) if match else None

    def _prune_old_scan_logs(self, keep_scans=LOG_KEEP_SCANS):
        """Keep logs + JSON summaries for only the latest N scans (by run_id timestamp)."""
        logs_dir = self.config.logs_dir
        if not os.path.isdir(logs_dir):
            return

        # Sweep orphaned atomic-write temps from summaries whose process died mid-write. Safe here
        # because this runs at scan START (via initial_cleanup), before the current run writes its
        # own summary tmp; the retention regex below anchors on .log/.json$ and never matches these.
        for name in os.listdir(logs_dir):
            if name.startswith("scan_summary_") and name.endswith(".tmp"):
                try:
                    os.remove(os.path.join(logs_dir, name))
                except OSError:
                    pass

        run_logs = defaultdict(list)
        for name in os.listdir(logs_dir):
            if not (name.endswith(".log") or name.endswith(".json")):
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

            self._prune_old_scan_logs(keep_scans=LOG_KEEP_SCANS)
            
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
            elif platform.system() == "Darwin":
                self._schedule_macos_cleanup()
                if hasattr(self.config, 'log_manager'):
                    self.config.log_manager.log_system("macOS cleanup LaunchDaemon scheduled")
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
        """Generate the cleanup script from the ACTUAL alert dir.

        Fixes the historical path-drift bug (P2): the old embedded base64 scripts
        targeted c:\\xdr-data\\alert / /opt/xdr-data/alert, which never matched the real
        <scanner_dir>/alert, so scheduled cleanup renamed nothing. Generating from
        config.alert_dir keeps the script and the data in lock-step.
        """
        alert_dir = self.config.alert_dir
        if platform.system() == "Windows":
            return (
                "@echo off\r\n"
                f'cd /d "{alert_dir}"\r\n'
                "if errorlevel 1 exit /b 0\r\n"
                "ren *.txt *.alert\r\n"
            )
        return (
            "#!/bin/bash\n"
            f'cd "{alert_dir}" || exit 0\n'
            "for file in *.txt; do\n"
            '    [ -e "$file" ] || continue\n'
            '    mv "$file" "${file%.txt}.alert"\n'
            "done\n"
        )

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

        except FileNotFoundError:
            # Host without systemd (minimal container, non-systemd init). Cleanup is
            # cosmetic (renames alert .txt -> .alert), so log-and-skip, never fail.
            logging.warning("systemctl not found - skipping Linux cleanup scheduling (cosmetic only)")
        except PermissionError:
            logging.warning("Linux cleanup scheduling requires root - skipping (cosmetic only)")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error scheduling Linux cleanup: {e}")

    def _schedule_macos_cleanup(self):
        """Schedule a one-shot cleanup via launchd (macOS has no systemd) — fixes P1
        where the old code wrote a systemd unit on Darwin and threw on every scan."""
        label = "com.yarascanner.cleanup"
        plist_path = f"/Library/LaunchDaemons/{label}.plist"
        plist = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n'
            '<dict>\n'
            f'    <key>Label</key><string>{label}</string>\n'
            '    <key>ProgramArguments</key>\n'
            '    <array>\n'
            '        <string>/bin/bash</string>\n'
            f'        <string>{self.config.cleanup_script}</string>\n'
            '    </array>\n'
            '    <key>RunAtLoad</key><true/>\n'
            '</dict>\n'
            '</plist>\n'
        )
        try:
            with open(plist_path, "w") as f:
                f.write(plist)
            subprocess.run(["launchctl", "load", plist_path], shell=False, check=True)
            logging.info("macOS cleanup LaunchDaemon loaded")
        except PermissionError:
            logging.warning("macOS cleanup scheduling requires root - skipping (cosmetic only)")
        except FileNotFoundError:
            logging.warning("launchctl not found - skipping macOS cleanup scheduling")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error scheduling macOS cleanup: {e}")


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

        self.log_manager = log_manager if log_manager else LogManager(config)
        self.stats_manager = stats_manager if stats_manager else StatisticsManager(config, self.log_manager)
        self._compile_source = "fresh"   # "cache" | "fresh" — surfaced in the scan summary
        self._compile_seconds = 0.0
        self.rules = self._load_or_compile_rules(config.yara_rule)
        
        self.files_scanned = 0
        self.files_skipped = 0
        self.skip_reasons = defaultdict(int)
        self.last_log_time = time.time()
        self.last_scanned_file = ""
        self.evidence_collector = EvidenceCollector(config)
        self.detection_counts = defaultdict(int)
        self.total_detections = 0
        self.results_uploader = ResultsUploader(config)
        self.lookup_uploader = LookupDatasetUploader(config, self.log_manager)
        self.lock_counts = threading.Lock()
        self.lock_files = threading.Lock()
        self.lock_alert = threading.Lock()
        self.lock_throttle = threading.Lock()

        self.status_uploader = ScanStatusUploader(config)
        self.results_uploader.log_manager = self.log_manager
        self.results_uploader.lookup_uploader = self.lookup_uploader

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
        self.total_paused_secs = 0.0     # wall-clock time >=1 worker was CPU-paused
        self.critical_pauses = 0         # pauses that hit the critical CPU threshold
        self._paused_workers = 0         # count of workers currently in the pause loop
        self._pause_wall_start = 0.0     # wall-clock start of the current throttled window
        self.queue_full_events = 0

        # Cancellation state (set by the cancel watcher / signal handlers).
        self.cancel_requested = False
        self.cancel_source = ""
        self.cancel_flag_path = os.path.join(getattr(config, "control_dir", config.scanner_dir), "cancel.flag")
        self.running_marker_path = os.path.join(getattr(config, "control_dir", config.scanner_dir), "running.json")
        self.cancel_watcher_thread = None
        # Earliest baseline (construction time) used to distinguish a genuinely stale
        # cancel flag from one delivered during the pre-scan compile phase. Never reset.
        self._process_started_at = time.time()
        self._scan_started_at = self._process_started_at  # reset to scan-phase start in scan_system
        self._last_heartbeat = 0.0
        self._scans_row_lock = threading.Lock()
        self._cancel_lock = threading.Lock()

        # Prime psutil's system-CPU sampler: the first cpu_percent(None) call always
        # returns 0.0, which would let the first throttle window through blind (P3).
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

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

    # ------------------------------------------------------------------
    # Cancellation + scan-lifecycle telemetry
    # ------------------------------------------------------------------
    def _request_cancel(self, source, log=True):
        """Cooperatively request cancellation. Idempotent (first source wins) and safe
        from any thread. NOT called from the signal handler — that sets the flags bare
        to stay async-signal-safe (no lock, no I/O)."""
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

        "Stale" = written before this process even started (mtime < process start, minus
        a small tolerance for coarse filesystem mtime). A cancel delivered DURING the
        pre-scan rule-compilation phase has a newer mtime and is deliberately preserved,
        so the watcher will honor it once it starts.
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
        """Poll for an operator cancel flag (written by a `mode=cancel` invocation).

        The flag was cleared at scan start, so any flag present now is a fresh cancel —
        no mtime comparison needed.
        """
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
            except Exception as e:
                self.log_manager.log_error(f"Cancel watcher error: {e}")
            time.sleep(CANCEL_POLL_SECS)

    def _write_running_marker(self, status):
        """Refresh the liveness marker that `mode=cancel` reports against.

        Written atomically (temp + os.replace) so a cross-process cancel reader never
        sees a half-written/empty file.
        """
        try:
            tmp = self.running_marker_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({
                    "scan_id": self.config.scan_id,
                    "run_id": getattr(self.config, "run_id", ""),
                    "pid": os.getpid(),
                    "hostname": self.config.hostname,
                    "started_at": self._scan_started_at,
                    "updated_at": time.time(),
                    "status": status,
                    "files_scanned": self.files_scanned,
                    "detections": self.total_detections,
                }, f)
            os.replace(tmp, self.running_marker_path)
        except Exception:
            pass

    def _remove_running_marker(self):
        try:
            if os.path.exists(self.running_marker_path):
                os.remove(self.running_marker_path)
        except Exception:
            pass

    def _emit_scan_row(self, status, message=""):
        """Append one scan-lifecycle row to the yara_scanner_scans lookup dataset."""
        lu = getattr(self, "lookup_uploader", None)
        if lu is None or not getattr(self.config, "write_dataset", True):
            return
        elapsed = max(0.0, time.time() - self._scan_started_at)
        # Snapshot volatile counters under the locks that guard their writers so the row
        # is a consistent instant (workers update files_scanned/total_detections under
        # lock_counts; the pause loop updates total_paused_secs under lock_throttle).
        with self.lock_counts:
            files_scanned = int(self.files_scanned)
            files_skipped = int(self.files_skipped)
            detections = int(self.total_detections)
        with self.lock_throttle:
            paused = round(self.total_paused_secs, 2)
        with self._scans_row_lock:
            row = {
                "tenant_id": getattr(self.config, "tenant_id", "unknown"),
                "scan_id": self.config.scan_id,
                "run_id": getattr(self.config, "run_id", ""),
                "scan_date": (getattr(self.config, "run_id", "") or "").split("_", 1)[0],
                "hostname": self.config.hostname,
                "os_info": self.config.os_info,
                "os_type": _os_type(),
                "ip_address": self.config.ip_addresses[0] if self.config.ip_addresses else "",
                "status": status,
                "scan_folder": str(getattr(self.config, "scan_folder", None) or "system"),
                "files_scanned": files_scanned,
                "files_skipped": files_skipped,
                "detections": detections,
                "valid_rules": int(self.config.error_logger.valid_rules_count),
                "failed_rules": int(self.config.error_logger.failed_rules_count),
                "scan_rate_fps": round(files_scanned / elapsed, 2) if elapsed > 0 else 0.0,
                "elapsed_secs": round(elapsed, 2),
                "total_paused_secs": paused,
                "throttle_mode": getattr(self.config, "throttle_mode", "script"),
                "posture": getattr(self.config, "posture", ""),
                "event_timestamp_ms": int(time.time() * 1000),
                "message": message or "",
            }
        try:
            lu.add_scan_row(row)
        except Exception as e:
            self.log_manager.log_error(f"Failed to emit scan-lifecycle row: {e}")

    def _maybe_heartbeat(self):
        """Emit a periodic 'running' lifecycle row + refresh the liveness marker."""
        now = time.time()
        if now - self._last_heartbeat >= SCANS_HEARTBEAT_SECS:
            self._last_heartbeat = now
            self._write_running_marker("running")
            self._emit_scan_row("running", "heartbeat")


    def _clean_rule_content(self, rule_lines, rule_name):
        """Normalize extracted rule block without mutating braces."""
        if not rule_lines:
            return None
        
        content = '\n'.join(rule_lines).strip()
        
        if not re.match(r'^\s*rule\s+\w+', content, re.IGNORECASE):
            logging.warning(f"Rule {rule_name} doesn't start with 'rule' keyword")
            return None
        return content

    def _is_valid_rule_structure(self, content, rule_name):
        """Basic validation for YARA rule structure."""
        try:
            if 'condition:' not in content.lower():
                logging.debug(f"Rule {rule_name} missing condition section")
                return False
            
            lines = content.split('\n')
            found_rule_line = False
            found_condition = False
            
            for line in lines:
                stripped = line.strip().lower()
                if stripped.startswith('rule '):
                    found_rule_line = True
                elif stripped.startswith('condition:'):
                    found_condition = True
            
            if not found_rule_line:
                logging.debug(f"Rule {rule_name} missing rule declaration line")
                return False
                
            if not found_condition:
                logging.debug(f"Rule {rule_name} missing condition line")
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

    def _rule_uses_unavailable_modules(self, rule_content, available_modules, source_imported_modules=None):
        """Return (True, module) if a rule REQUIRES a YARA module missing on this agent.

        A rule can require a module two ways, and both mean it can never compile here, so it
        must be SKIPPED (module unavailable), not counted as a FAILED compilation:
          1. an explicit `import "<module>"` line inside the rule block, or
          2. a reference to `<module>.<field>` whose declaring top-level import was dropped from
             the preamble by _split_yara_rules (because the module is unavailable). The split
             rule body then has no import line but still uses the module; previously it fell
             through to yara.compile, raised `undefined identifier`, and was mis-counted as FAILED.

        Case (2) is gated on the module actually being imported SOMEWHERE in the original source
        (`source_imported_modules`). A bare `cuckoo.` in a rule that never imported cuckoo is just
        literal text (a hunt string / comment / meta value) — it compiles and matches fine, so it
        must NOT be skipped. Without this gate, a rule looking for the *string* "cuckoo.conf" was
        silently dropped on a cuckoo-less agent.
        """
        # (1) explicit inline import of an unavailable module
        import_pattern = r'^\s*import\s+"?(\w+)"?'
        for line in rule_content.split('\n'):
            match = re.match(import_pattern, line.strip())
            if match:
                module_name = match.group(1)
                if module_name not in available_modules:
                    logging.debug(f"Rule imports unavailable module: {module_name}")
                    return True, module_name

        # (2) usage of a module that the source imported but this agent lacks
        if source_imported_modules:
            for module_name, usage_pattern in MODULE_USAGE_PATTERNS.items():
                if module_name in available_modules:
                    continue
                if module_name not in source_imported_modules:
                    continue  # bare "<mod>." here is a literal string/comment, not a module ref
                if re.search(usage_pattern, rule_content):
                    logging.debug(f"Rule uses unavailable imported module via reference: {module_name}")
                    return True, module_name

        return False, None

    def _extract_imported_modules(self, source_text):
        """Extract imported YARA module names from a source block."""
        imported = set()
        import_pattern = re.compile(r'(?m)^\s*import\s+"?(\w+)"?')
        for match in import_pattern.finditer(source_text or ""):
            imported.add(match.group(1))
        return imported

    def _inject_missing_rule_imports(self, rule_content, available_modules, preamble_imports=None):
        """Inject missing module imports required by a rule based on module usage."""
        preamble_imports = preamble_imports or set()
        already_imported = self._extract_imported_modules(rule_content) | set(preamble_imports)

        module_usage_patterns = MODULE_USAGE_PATTERNS  # shared table (see _rule_uses_unavailable_modules)

        missing = []
        for module_name, usage_pattern in module_usage_patterns.items():
            if re.search(usage_pattern, rule_content):
                if module_name in available_modules and module_name not in already_imported:
                    missing.append(module_name)

        if not missing:
            return rule_content, []

        import_block = "\n".join(f'import "{m}"' for m in missing)
        return f"{import_block}\n{rule_content}", missing

    # ---- rule-compilation disk cache -------------------------------------------------------
    def _rule_cache_dir(self):
        d = os.path.join(self.config.scanner_dir, "rule_cache")
        os.makedirs(d, exist_ok=True)
        return d

    def _rule_cache_key(self, yara_rule_string, available_modules):
        """Key the cache on everything that determines the compiled bundle: the exact rule text,
        the module set (drives skip/inject), the declared externals, the yara/platform version,
        and a format tag (bump RULE_CACHE_FORMAT whenever the compile/split/inject logic changes).
        Because compilation is a pure function of these inputs, the key can never drift from what
        would actually be produced — no need to replay the per-rule transform to build it."""
        h = hashlib.sha256()
        h.update(("FMT:%s\n" % RULE_CACHE_FORMAT).encode())
        h.update(("YARA:%s\n" % _yara_version_tag()).encode())
        h.update(("EXT:%s\n" % json.dumps(YARA_COMPILE_EXTERNALS, sort_keys=True)).encode())
        h.update(("MODS:%s\n" % ",".join(sorted(available_modules))).encode())
        h.update(b"RULES:")
        h.update((yara_rule_string or "").encode("utf-8", "replace"))
        return h.hexdigest()

    def _restore_cache_meta(self, cache_path, rules=None):
        """On a cache HIT the per-rule loop is skipped, so restore the valid/failed/skipped counts
        from the sidecar written at save time — otherwise the scan summary would report 0 rules."""
        meta_path = cache_path + ".meta.json"
        el = self.config.error_logger
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            el.valid_rules_count = int(meta.get("valid_rules", 0))
            el.failed_rules_count = int(meta.get("failed_rules", 0))
            return int(meta.get("skipped", 0))
        except Exception:
            # No/broken sidecar: recover the true valid count from the loaded bundle
            # (yara.Rules is iterable and yields exactly the compiled rules).
            if not getattr(el, "valid_rules_count", 0):
                try:
                    el.valid_rules_count = sum(1 for _ in rules) if rules is not None else 1
                except Exception:
                    el.valid_rules_count = 1
            return 0

    def _save_rule_cache(self, rules, cache_path, yara_rule_string):
        """Persist the compiled ruleset + a counts sidecar, atomically. Best-effort (a read-only
        or full disk just means no caching); never fatal to the scan."""
        el = self.config.error_logger
        with _RULE_CACHE_LOCK:
            tmp = "%s.%d.%08x.tmp" % (cache_path, os.getpid(), random.getrandbits(32))
            try:
                rules.save(tmp)
                os.replace(tmp, cache_path)
                meta = {
                    "valid_rules": int(getattr(el, "valid_rules_count", 0)),
                    "failed_rules": int(getattr(el, "failed_rules_count", 0)),
                    "skipped": int(getattr(el, "skipped_rules_count", 0)),
                    "yara": _yara_version_tag(),
                    "format": RULE_CACHE_FORMAT,
                }
                with open(cache_path + ".meta.json", "w", encoding="utf-8") as f:
                    json.dump(meta, f)
                self._prune_rule_cache()
            except Exception as e:
                self.log_manager.log_system(f"Rule cache save failed (non-fatal): {e}")
                for p in (tmp,):
                    try:
                        if os.path.exists(p):
                            os.remove(p)
                    except OSError:
                        pass

    def _prune_rule_cache(self):
        """LRU-bound the cache dir by file count and total bytes (newest kept)."""
        try:
            d = self._rule_cache_dir()
            names = os.listdir(d)
            # Sweep stale save-temps orphaned by a crash between rules.save(tmp) and os.replace().
            # Age-gate so a concurrent in-flight save from another per-action process is spared.
            now = time.time()
            for n in names:
                if n.startswith("rules_") and n.endswith(".tmp"):
                    p = os.path.join(d, n)
                    try:
                        if now - os.path.getmtime(p) > 3600:
                            os.remove(p)
                    except OSError:
                        pass
            files = [os.path.join(d, f) for f in names
                     if f.startswith("rules_") and f.endswith(".yarac")]
            files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            kept, total = 0, 0
            for p in files:
                total += os.path.getsize(p)
                kept += 1
                if kept > RULE_CACHE_MAX_FILES or total > RULE_CACHE_MAX_BYTES:
                    for q in (p, p + ".meta.json"):
                        try:
                            os.remove(q)
                        except OSError:
                            pass
        except Exception:
            pass

    def _load_or_compile_rules(self, yara_rule_string):
        """Return a compiled ruleset, using the disk cache when the exact rules were compiled
        before on this endpoint+engine. Falls back to a fresh compile on any cache miss/failure."""
        t0 = time.perf_counter()
        self._compile_source, self._compile_seconds = "fresh", 0.0
        cache_path = None
        if RULE_CACHE_ENABLED:
            try:
                available_modules = self._get_available_yara_modules()
                key = self._rule_cache_key(yara_rule_string, available_modules)
                cache_path = os.path.join(self._rule_cache_dir(), "rules_%s.yarac" % key[:40])
                if os.path.exists(cache_path):
                    rules = yara.load(cache_path)  # raises on cross-version / corrupt bundle
                    # Prove the bundle is usable AND still accepts the per-file externals the
                    # scanner overrides at match time — fail HERE (and fall back) not mid-scan.
                    rules.match(data=b"", externals={"filepath": "", "filename": ""})
                    try:
                        os.utime(cache_path, None)  # LRU touch
                    except OSError:
                        pass
                    skipped = self._restore_cache_meta(cache_path, rules)
                    self._compile_source = "cache"
                    self._compile_seconds = time.perf_counter() - t0
                    self.log_manager.log_system(
                        "Rule cache HIT %s load=%.2fs (valid=%s failed=%s skipped=%s)" % (
                            os.path.basename(cache_path), self._compile_seconds,
                            self.config.error_logger.valid_rules_count,
                            self.config.error_logger.failed_rules_count, skipped))
                    return rules
            except Exception as e:
                self.log_manager.log_system("Rule cache miss/unusable, compiling fresh: %s" % e)
                if cache_path and os.path.exists(cache_path):
                    for q in (cache_path, cache_path + ".meta.json"):
                        try:
                            os.remove(q)
                        except OSError:
                            pass

        rules = self._compile_yara_rules(yara_rule_string)   # existing ~90s path, unchanged
        self._compile_source, self._compile_seconds = "fresh", time.perf_counter() - t0
        self.log_manager.log_system("Rule compile FRESH %.2fs" % self._compile_seconds)
        if RULE_CACHE_ENABLED and cache_path:
            self._save_rule_cache(rules, cache_path, yara_rule_string)
        return rules

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
        # Modules imported ANYWHERE in the original source — used to tell a real (but dropped)
        # module reference apart from a rule that merely contains "<mod>." as a literal string.
        source_imported = self._extract_imported_modules(yara_rule_string)
        logging.info(f"Starting compilation of {len(individual_rules)} YARA rules...")

        for i, rule_content in enumerate(individual_rules, 1):
            name_match = re.search(r'rule\s+(\w+)', rule_content, re.IGNORECASE)
            display_name = name_match.group(1) if name_match else f"rule_{i}"

            uses_unavailable, missing_module = self._rule_uses_unavailable_modules(
                rule_content, available_modules, source_imported
            )
            
            if uses_unavailable:
                skipped_count += 1
                if skipped_count <= 10:
                    logging.warning(f"Skipping rule '{display_name}': requires unavailable module "
                                    f"'{missing_module}' (not on this agent - not a compile failure)")
                    error_logger.error_logger.warning(
                        f"SKIP (module unavailable): rule '{display_name}' requires '{missing_module}'")
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

        error_logger.skipped_rules_count = skipped_count  # persist so a cache HIT can restore it
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
        lines = yara_rule_string.splitlines()
        
        imports = []
        imports_seen = set()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('import ') or stripped.startswith('include '):
                if stripped not in imports_seen:
                    if available_modules is not None:
                        import_match = re.search(r'import\s+"([^"]+)"', stripped)
                        if import_match:
                            module_name = import_match.group(1)
                            if module_name in available_modules:
                                imports.append(line)
                                imports_seen.add(stripped)
                            else:
                                logging.debug(f"Skipping unavailable module in preamble: {module_name}")
                        else:
                            imports.append(line)
                            imports_seen.add(stripped)
                    else:
                        imports.append(line)
                        imports_seen.add(stripped)
                        
        logging.info(f"Found {len(imports)} unique import statements")
        
        rule_starts = []
        for i, line in enumerate(lines):
            if re.match(r'^\s*rule\s+\w+', line, re.IGNORECASE):
                rule_name_match = re.search(r'rule\s+(\w+)', line, re.IGNORECASE)
                rule_name = rule_name_match.group(1) if rule_name_match else f"rule_{len(rule_starts)+1}"
                rule_starts.append((i, rule_name))
        
        logging.info(f"Found {len(rule_starts)} rule start positions")
        
        rules = []
        successful_extractions = 0
        failed_extractions = 0
        
        for idx, (start_line, rule_name) in enumerate(rule_starts):
            try:
                if idx + 1 < len(rule_starts):
                    end_line = rule_starts[idx + 1][0]
                else:
                    end_line = len(lines)
                
                rule_lines = lines[start_line:end_line]
                rule_content = self._clean_rule_content(rule_lines, rule_name)
                
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
            
            return base_stats

    def _calculate_cache_hit_rate(self):
        """Calculate current cache hit rate."""
        cache_stats = self.stats_manager.cache_stats
        total_requests = cache_stats['hits'] + cache_stats['misses']
        if total_requests > 0:
            return (cache_stats['hits'] / total_requests) * 100
        return 0

    def _sample_system_cpu(self):
        """Return a system-CPU% reading, cached at throttle_check_interval_secs cadence
        so concurrent workers share one measurement instead of hammering psutil."""
        now = time.time()
        with self.lock_throttle:
            if (now - self.last_throttle_check) >= self.config.throttle_check_interval_secs:
                try:
                    self.last_system_cpu = psutil.cpu_percent(interval=None)
                except Exception:
                    self.last_system_cpu = 0.0
                self.last_throttle_check = now
            return self.last_system_cpu

    def _maybe_throttle_scanning(self, force=False):
        """Pause the calling worker while system CPU is above the high threshold.

        Enhanced sleep logic (customer request): rather than a single fixed micro-sleep,
        the worker stays paused and RE-CHECKS CPU each interval, resuming only once CPU
        falls below the resume threshold (high - resume_margin, i.e. hysteresis to avoid
        flapping). Bounded by max_pause_secs so a permanently busy host still makes
        forward progress. No-op unless throttle_mode='script' (OS/off modes hand pacing
        to the kernel). `force` is accepted for call-site compatibility; the CPU gate is
        the same either way.
        """
        if not getattr(self.config, "light_throttle_enabled", False):
            return

        cpu = self._sample_system_cpu()
        if cpu < self.config.high_cpu_threshold:
            return  # fast path: machine is not under pressure

        resume_threshold = max(1.0, self.config.high_cpu_threshold - self.config.resume_margin)
        interval = max(0.05, self.config.throttle_check_interval_secs)
        max_pause = self.config.max_pause_secs
        pause_started = time.time()
        entered_critical = cpu >= self.config.critical_cpu_threshold

        # Track WALL-CLOCK throttled time (the span during which >=1 worker is paused),
        # not the sum of per-worker pause seconds — otherwise N concurrent workers would
        # inflate total_paused_secs by ~N. First worker in opens the window; last one out
        # closes it and adds the elapsed wall time.
        with self.lock_throttle:
            if self._paused_workers == 0:
                self._pause_wall_start = pause_started
            self._paused_workers += 1
        try:
            while self.scan_active and not self.cancel_requested:
                time.sleep(interval)
                cpu = self._sample_system_cpu()
                if cpu >= self.config.critical_cpu_threshold:
                    entered_critical = True
                if cpu < resume_threshold:
                    break
                if max_pause and (time.time() - pause_started) >= max_pause:
                    self.log_manager.log_performance(
                        f"Throttle pause hit max_pause_secs ({max_pause:.0f}s) at CPU {cpu:.0f}% - "
                        f"resuming to guarantee forward progress"
                    )
                    break
        finally:
            with self.lock_throttle:
                self._paused_workers -= 1
                if self._paused_workers <= 0:
                    self._paused_workers = 0
                    self.total_paused_secs += time.time() - self._pause_wall_start
                if entered_critical:
                    self.critical_pauses += 1

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
            # Populate the filename/filepath externals per file so rules that key off them work.
            matches = self.rules.match(
                filepath=file_path,
                externals={"filepath": file_path, "filename": os.path.basename(file_path)},
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
        # Force-scan allowlist wins over all path-based skips (fragments + platform
        # skip dirs): browser caches/profiles are scanned even if a broader rule excludes
        # them. Filename/extension skips above still apply (no point scanning a .iso).
        if any(fragment in portable_path for fragment in getattr(self.config, "force_scan_fragments", ())):
            return False
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
                    file_creation_time=file_creation_time
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
                    'detection_timestamp': datetime.datetime.now().isoformat()
                }
            )

    def _debug_rule_analysis(self, yara_rule_string):
        """Debug analysis of YARA rules file structure."""
        lines = yara_rule_string.splitlines()
        
        logging.info("=== YARA FILE ANALYSIS ===")
        logging.info(f"Total lines: {len(lines)}")
        
        rule_declarations = []
        for i, line in enumerate(lines):
            if re.match(r'^\s*rule\s+\w+', line, re.IGNORECASE):
                rule_name_match = re.search(r'rule\s+(\w+)', line, re.IGNORECASE)
                rule_name = rule_name_match.group(1) if rule_name_match else "unnamed"
                rule_declarations.append((i+1, rule_name))
        
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
        
        import_count = len([line for line in lines if line.strip().startswith('import ')])
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

        # Emit the terminal lifecycle row now that workers have drained and counts are
        # final, but BEFORE the uploaders are stopped so the row is actually sent.
        if self.cancel_requested:
            _term_status = "cancelled"
            _term_msg = f"cancelled by operator (source={self.cancel_source})"
        elif self.scan_failed:
            _term_status = "failed"
            _term_msg = "; ".join(self.failure_reasons[:3]) or "scan failed"
        else:
            _term_status = "completed"
            _term_msg = "scan completed"
        self._emit_scan_row(_term_status, _term_msg)

        try:
            if hasattr(self, "results_uploader") and self.results_uploader:
                self.results_uploader.stop(wait=True)
            if hasattr(self, "lookup_uploader") and self.lookup_uploader:
                self.lookup_uploader.stop(wait=True)
        except Exception as e:
            self.log_manager.log_error(f"Error stopping uploaders: {e}")

        self.log_manager.log_system(f"Enhanced cleanup completed in {cleanup_total_time:.1f} seconds")

    def scan_system(self):
        """Main system scan orchestration."""
        start_time = time.time()
        self._scan_started_at = start_time
        self._last_heartbeat = start_time  # first heartbeat waits a full interval
        # Start watching for an operator cancel flag and announce the scan started.
        self._start_cancellation_watcher()
        self._emit_scan_row("initiated", "scan initiated")

        self.resource_monitor = None
        if self.config.enable_resource_monitoring:
            self.resource_monitor = SystemResourceMonitor(self.config, self.log_manager)

        self.log_manager.log_system("=== ENHANCED SYSTEM SCAN INITIATED ===")
        self.log_manager.log_system(
            "All monitoring systems activated",
            {
                'statistics_monitoring': True,
                'performance_monitoring': self.config.enable_performance_monitoring,
                'resource_monitoring': self.config.enable_resource_monitoring,
                'match_upload_enabled': UPLOAD_RESULTS,
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
                        self._maybe_heartbeat()

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
            # The terminal lifecycle row is emitted inside _perform_enhanced_cleanup,
            # after workers drain (so counts are final) and before uploaders stop.
            self._perform_enhanced_cleanup(start_time, total_files_found, files_per_target)
            self._remove_running_marker()
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
                'scan_start_time': datetime.datetime.fromtimestamp(scanner.scan_start_time).isoformat(),
                'scan_end_time': datetime.datetime.now().isoformat(),
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
        
        efficiency_score = 100
        if final_report_data['file_processing']['total_files_processed'] > 0:
            skip_rate = final_report_data['file_processing']['total_files_skipped'] / final_report_data['file_processing']['total_files_processed']
            efficiency_score -= (skip_rate * 20)
        
        if final_report_data['rule_compilation']['total_rules_processed'] > 0:
            rule_failure_rate = final_report_data['rule_compilation']['failed_rules_skipped'] / final_report_data['rule_compilation']['total_rules_processed']
            efficiency_score -= (rule_failure_rate * 30)
        
        final_report_data['efficiency_score'] = max(0, efficiency_score)

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


def run(yarafile=None, scan_folder=None, alert_severity="low", mode=None, options=None,
        create_alerts=None, write_dataset=None, collect_files=None, throttle_mode=None,
        cpu_high_threshold=None, cpu_critical_threshold=None, max_pause_secs=None, tenant_id=None,
        lookup_shard=None):
    """Full scanner implementation (internal API).

    Operators do NOT call this directly through the Action Center — use the `main` entry point,
    whose only inputs are yarafile / scan_folder / alert_severity. Every other behaviour knob
    defaults to its CUSTOMER CONFIG constant at the top of this file (edit once per deployment).
    Any knob left unset (None) falls back to its CONFIG_* constant; an explicit `options`
    "key=value,key=value" entry still OVERRIDES the constant. `mode="cancel"` short-circuits to
    deliver a cancel flag for a running scan instead of starting one.
    """
    # Fall back to the CUSTOMER CONFIG constants for anything not explicitly supplied.
    if mode is None:
        mode = CONFIG_MODE
    if options is None:
        options = CONFIG_OPTIONS
    if create_alerts is None:
        create_alerts = CONFIG_CREATE_ALERTS
    if write_dataset is None:
        write_dataset = CONFIG_WRITE_DATASET
    if collect_files is None:
        collect_files = CONFIG_COLLECT_FILES
    if throttle_mode is None:
        throttle_mode = CONFIG_THROTTLE_MODE
    if cpu_high_threshold is None:
        cpu_high_threshold = CONFIG_CPU_HIGH_THRESHOLD
    if cpu_critical_threshold is None:
        cpu_critical_threshold = CONFIG_CPU_CRITICAL_THRESHOLD
    if max_pause_secs is None:
        max_pause_secs = CONFIG_MAX_PAUSE_SECS
    if tenant_id is None:
        tenant_id = CONFIG_TENANT_ID
    if lookup_shard is None:
        lookup_shard = CONFIG_LOOKUP_SHARD

    # Resolve the compact options string over the explicit kwargs (options win).
    opts = _parse_options_string(options)

    def _pick(key, current):
        return opts.get(key, current)

    create_alerts = _pick("create_alerts", create_alerts)
    write_dataset = _pick("write_dataset", write_dataset)
    collect_files = _pick("collect_files", collect_files)
    throttle_mode = _pick("throttle_mode", throttle_mode)
    cpu_high_threshold = _pick("cpu_high_threshold", cpu_high_threshold)
    cpu_critical_threshold = _pick("cpu_critical_threshold", cpu_critical_threshold)
    max_pause_secs = _pick("max_pause_secs", max_pause_secs)
    tenant_id = _pick("tenant_id", tenant_id)
    lookup_shard = _pick("lookup_shard", lookup_shard)

    mode = (str(mode) if mode is not None else "scan").strip().lower() or "scan"
    if mode == "cancel":
        return _handle_cancel_request(tenant_id_override=tenant_id)

    config = None
    log_manager = None
    stats_manager = None
    exception_logger = None
    scanner = None

    try:
        config = ScanConfig(
            yarafile,
            scan_folder=scan_folder,
            alert_severity=alert_severity,
            mode=mode,
            create_alerts=create_alerts,
            write_dataset=write_dataset,
            collect_files=collect_files,
            throttle_mode=throttle_mode,
            cpu_high_threshold=cpu_high_threshold,
            cpu_critical_threshold=cpu_critical_threshold,
            max_pause_secs=max_pause_secs,
            tenant_id=tenant_id,
            lookup_shard=lookup_shard,
        )
        log_manager = LogManager(config)

        # Fail loud on un-configured credentials BEFORE scanning: if the API creds are still the
        # 'replace_with_*' placeholders and this run intends to deliver (alerts and/or datasets),
        # a full scan would find matches but drop 100% of them. Abort now with a clear message in
        # the SCAN_RESULT the operator sees, instead of wasting the scan and silently losing data.
        # Use the PARSED booleans on config, not the raw run() args — an options string passes
        # "false" (a truthy non-empty string), which config.__init__ has already coerced to bool.
        if getattr(config, "creds_placeholder", False) and (config.create_alerts or config.write_dataset):
            msg = (
                "SCAN ABORTED — XDR API credentials are not set. DEFAULT_XDR_API_KEY / "
                "DEFAULT_XDR_API_ID / DEFAULT_XDR_API_URL are still 'replace_with_*' placeholders, "
                "so no alerts or lookup datasets can be delivered (every upload fails with 'No "
                "scheme supplied'). Edit those three lines at the top of the script with your real "
                "Advanced API key + https tenant URL and re-upload. "
                "(To scan locally without delivery, set CONFIG_CREATE_ALERTS and CONFIG_WRITE_DATASET "
                "to False.)"
            )
            log_manager.log_error(msg)
            try:
                log_manager.stop_logging()
            except Exception:
                pass
            return msg

        _apply_light_process_priority(log_manager, throttle_mode=config.throttle_mode)
        exception_logger = config.exception_logger
        stats_manager = StatisticsManager(config, log_manager)
        cleanup_manager = CleanupManager(config)

        cleanup_manager.initial_cleanup()
        log_manager.log_system("Initial cleanup completed")

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
            'xdr_api_key_source': config.api_key_source,
            'xdr_api_id_source': config.api_id_source,
            'xdr_api_url_source': config.api_url_source,
            'xdr_api_url': XDR_API_URL,
            'default_alert_severity': config.alert_severity,
            'match_only_upload_mode': not UPLOAD_NON_MATCH_DATA,
            'logging_format': 'standardized'
        }
        
        log_manager.log_system("YARA Scanner initialization completed", init_data)
        
        if config.scan_folder and config.scan_folder.lower() != "default":
            scope_message = f"SCAN SCOPE: Limited to specified targets: {config.scan_targets}"
        else:
            scope_message = "SCAN SCOPE: Full system scan (light profile throttling enabled)"
        
        log_manager.log_system(scope_message, {'scan_targets': getattr(config, 'scan_targets', 'default')})
        
        rule_count = len(re.findall(r'rule\s+\w+', config.yara_rule, re.IGNORECASE))
        import_count = len(re.findall(r'import\s+', config.yara_rule, re.IGNORECASE))
        
        rules_data = {
            'total_rules_found': rule_count,
            'import_statements': import_count,
            'rule_content_length': len(config.yara_rule)
        }
        
        log_manager.log_system(f"YARA Rules loaded: {rule_count} rules, {import_count} imports", rules_data)

        log_manager.log_system("YARA Scanner initialized successfully", init_data)

        scanner = YaraScanner(config, log_manager=log_manager, stats_manager=stats_manager)
        if scanner.file_cache:
            scanner.file_cache.log_manager = log_manager

        # Route POSIX termination signals into the same graceful cancel path so a hard
        # Action-Center abort (where a signal is delivered) still drains cleanly. The
        # handler sets the flags BARE (no lock, no logging) to stay async-signal-safe;
        # the watcher/main loop observe cancel_requested and drive the graceful shutdown.
        try:
            import signal as _signal

            def _sig_cancel(signum, _frame):
                scanner.cancel_source = f"signal:{signum}"
                scanner.cancel_requested = True
                scanner.scan_active = False

            for _sig_name in ("SIGTERM", "SIGINT"):
                _sig = getattr(_signal, _sig_name, None)
                if _sig is not None:
                    try:
                        _signal.signal(_sig, _sig_cancel)
                    except Exception:
                        pass
        except Exception:
            pass

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

        # Operator-initiated cancellation is a success outcome (not a failure).
        if scanner.cancel_requested:
            log_manager.log_system(f"Scan cancelled by operator (source={scanner.cancel_source})")
            return (
                f"Scan cancelled by operator: {scanner.files_scanned} files scanned | "
                f"{scanner.total_detections} matches found | {config.posture}"
            )

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
            'log_generation_stats': final_log_stats,
            'error_summary': {
                'compilation_errors': error_logger.failed_rules_count,
                'scan_errors': sum(1 for reason in scanner.skip_reasons.keys() if 'error' in reason.lower())
            }
        }

        log_manager.log_system(
            f"Scan completed successfully in {datetime.timedelta(seconds=int(scan_total_time))}",
            comprehensive_final_stats
        )

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
        
        if 'scanner' in locals() and hasattr(scanner, 'scan_threads'):
            remaining_threads = [t for t in scanner.scan_threads if t.is_alive()]
            if remaining_threads:
                log_manager.log_system(f"Waiting for {len(remaining_threads)} remaining threads to terminate")
                for t in remaining_threads:
                    t.join(timeout=2)
                    
        log_manager.log_system("=== YARA SCANNER COMPLETED SUCCESSFULLY (STANDARDIZED) ===")

        summary = (f"Scan completed: {scanner.files_scanned} files scanned | "
                f"{error_logger.failed_rules_count} rules failed compilation | "
                f"{scanner.total_detections} matches found | "
                f"paused {scanner.total_paused_secs:.0f}s | {config.posture}")
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

        failed_rules = config.error_logger.failed_rules_count if config and hasattr(config, 'error_logger') else 0
        # scanner is initialized to None at the top of main(), so `'scanner' in locals()`
        # is always true — guard on the object itself (an early failure leaves it None).
        files_scanned = scanner.files_scanned if scanner is not None else 0
        matches = scanner.total_detections if scanner is not None else 0

        # A crash reaching here IS a failed scan — record it so the finally-block's
        # scan_summary derives outcome="failed" instead of the default "completed".
        if scanner is not None:
            scanner.scan_failed = True

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
            if 'scanner' in locals() and hasattr(scanner, "lookup_uploader") and scanner.lookup_uploader:
                scanner.lookup_uploader.stop(wait=True)
            # Machine-readable per-scan summary, written AFTER the uploaders drain so the
            # alert/dataset delivery counts are final. One JSON per run for tools to consume.
            if log_manager and config is not None and scanner is not None:
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
                    _el = config.error_logger if hasattr(config, "error_logger") else None
                    _det = getattr(scanner, "detection_counts", {}) or {}
                    log_manager.write_scan_summary({
                        "outcome": _outcome,
                        "scan_folder": getattr(config, "scan_folder", None),
                        "duration_secs": round(_dur, 2) if _dur is not None else None,
                        "files_scanned": getattr(scanner, "files_scanned", None),
                        "files_skipped": getattr(scanner, "files_skipped", None),
                        "matches": getattr(scanner, "total_detections", None),
                        "unique_rules_triggered": len(_det),
                        "failed_rules": getattr(_el, "failed_rules_count", None),
                        "valid_rules": getattr(_el, "valid_rules_count", None),
                        "scan_rate_fps": (round(getattr(scanner, "files_scanned", 0) / _dur, 2)
                                          if _dur and _dur > 0 else 0),
                        "total_paused_secs": round(getattr(scanner, "total_paused_secs", 0) or 0, 2),
                        "throttle_mode": getattr(config, "throttle_mode", None),
                        "compile_source": getattr(scanner, "_compile_source", None),
                        "compile_seconds": round(getattr(scanner, "_compile_seconds", 0) or 0, 2),
                        "cancel_source": getattr(scanner, "cancel_source", None),
                        "alert_delivery": (scanner.results_uploader.get_upload_stats()
                                           if hasattr(scanner, "results_uploader") and scanner.results_uploader else {}),
                        "dataset_delivery": (dict(getattr(scanner.lookup_uploader, "upload_stats", {}))
                                             if hasattr(scanner, "lookup_uploader") and scanner.lookup_uploader else {}),
                        "top_rules": sorted(_det.items(), key=lambda rc: rc[1], reverse=True)[:10],
                    })
                except Exception as _se:
                    log_manager.log_error(f"scan summary write failed: {_se}")
            if log_manager:
                log_manager.stop_logging()
        except Exception as cleanup_error:
            sys.stderr.write(f"Error during final cleanup: {cleanup_error}\n")
            sys.stderr.flush()


# ============================================================================
# ACTION CENTER ENTRY POINTS
# ---------------------------------------------------------------------------
# Cortex XDR's "Run by entry point" turns each parameter of the selected function
# into an input field the operator fills in. To keep that list short, `main` takes
# ONLY the three things that change per run — yarafile, scan_folder, alert_severity.
# Every other behaviour knob lives in the CUSTOMER CONFIG block at the top of this
# file; edit it once and re-upload. Pick the `cancel` entry point to stop a scan.
# ============================================================================
def main(yarafile=None, scan_folder=None, alert_severity="low"):
    """Action Center entry point — run a YARA scan. Only these 3 inputs are shown to the
    operator; all other behaviour comes from the CUSTOMER CONFIG constants at the top."""
    return run(yarafile, scan_folder, alert_severity)


def cancel():
    """Action Center entry point — cancel a running scan on this endpoint (no inputs)."""
    return run(mode="cancel")


if __name__ == "__main__":
    try:
        # Ordered params (matches the XDR script_input order):
        #   1 yarafile  2 scan_folder  3 alert_severity  4 mode  5 options
        # Only 1-3 are typically needed now — mode/options fall back to CONFIG_MODE/CONFIG_OPTIONS
        # (and every other behaviour knob to its CUSTOMER CONFIG constant) when left blank.
        # An empty string for any input selects the CONFIG_* default.
        def _argv(i):
            return sys.argv[i] if len(sys.argv) > i and str(sys.argv[i]).strip() else None

        yarafile_arg = _argv(1)
        scan_folder_arg = _argv(2)
        alert_severity_arg = _parse_alert_severity(_argv(3), "alert_severity") if _argv(3) else "low"
        mode_arg = _argv(4)      # blank -> CONFIG_MODE
        options_arg = _argv(5)   # blank -> CONFIG_OPTIONS

        result = run(
            yarafile_arg,
            scan_folder_arg,
            alert_severity_arg,
            mode=mode_arg,
            options=options_arg,
        )

        result_text = str(result or "")
        low = result_text.lower()
        is_success = bool(result_text) and not (
            low.startswith("scan failed") or low.startswith("cancel failed") or low.startswith("scan aborted")
        )
        sys.exit(0 if is_success else 1)

    except Exception as e:
        error_msg = f"Critical startup error: {str(e)}"
        sys.stderr.write(f"{error_msg}\n")
        sys.stderr.write(f"Full traceback:\n{traceback.format_exc()}\n")
        sys.stderr.flush()
        sys.exit(1)
