#!/usr/bin/env python3
"""The runtime profile and the proxy settings - the two things a customer edits here.

The profile existed in name only. `light_profile` was hardcoded True and read nowhere, the
startup log announced "Light profile active: reduced workers, reduced monitoring" on every
run, and the scan summary reported `scanner_profile: 'light'` unconditionally. None of it
changed behaviour, so a report saying "light profile" was describing a setting that did not
exist - which is worse than saying nothing, because it is checkable and wrong.

Proxy support did not exist at all. An endpoint that must egress through a proxy had no way
to say so: requests honours HTTPS_PROXY only when the process environment carries it, and an
Action Center script's does not - it gets three inputs and no environment.
"""
import base64
import importlib.util
import os
import tempfile

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PY = os.path.join(_REPO, "xdr", "xdr_yara_scanner.py")
_RULES = base64.b64encode(b"rule T {\n  condition:\n    false\n}\n").decode()


def _load():
    """Fresh import each time - the profile is read at ScanConfig construction from an env
    var that these tests set, and a cached module would carry the previous value."""
    tmp = tempfile.mkdtemp(prefix="yarascn_")
    spec = importlib.util.spec_from_file_location("scanner_under_test", _PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m._default_scanner_dir = lambda: tmp
    return m


def _cfg(mod):
    return mod.ScanConfig(yarafile=_RULES, scan_folder="default")


@pytest.fixture
def scanner():
    return _load()


# ------------------------------------------------------------------ profile
def test_the_default_profile_runs_the_diagnostics(scanner):
    """Both monitors on by default. They are what make a slow or stalled scan explainable
    afterwards, and a scan is not frequent enough for the sampling thread to be a cost worth
    defaulting away from."""
    assert scanner.CONFIG_PROFILE == "full"
    c = _cfg(scanner)
    assert c.profile == "full"
    assert c.light_profile is False
    assert c.enable_performance_monitoring is True
    assert c.enable_resource_monitoring is True


def test_light_profile_actually_turns_the_monitors_off(monkeypatch):
    """The property the name promises. Previously the name promised it and nothing did it."""
    monkeypatch.setenv("YARA_PROFILE", "light")
    c = _cfg(_load())
    assert c.profile == "light"
    assert c.light_profile is True
    assert c.enable_performance_monitoring is False
    assert c.enable_resource_monitoring is False
    assert c.enable_fd_monitoring is False


def test_light_profile_does_not_touch_workers_or_cpu(monkeypatch):
    """It never did, whatever the old startup message said. Worker count and CPU impact are
    CONFIG_WORKERS and the CPU governor, and they apply to both profiles - so a reader who
    picks `light` expecting a gentler scan must not get one silently, they must be told to
    use the governor."""
    plain = _cfg(_load())
    monkeypatch.setenv("YARA_PROFILE", "light")
    light = _cfg(_load())
    assert light.max_workers == plain.max_workers
    assert light.cpu_guarantee == plain.cpu_guarantee


def test_an_unknown_profile_is_rejected_not_guessed(monkeypatch):
    """A typo must not silently select a posture. There are two values and no near-misses
    worth guessing between."""
    monkeypatch.setenv("YARA_PROFILE", "medium")
    with pytest.raises(ValueError, match="full.*light"):
        _cfg(_load())


def test_the_summary_reports_the_profile_that_actually_ran():
    """It was hardcoded to 'light' regardless of anything, so the one field telling an
    operator which profile ran always said the same thing."""
    src = open(_PY, encoding="utf-8").read()
    assert "'scanner_profile': 'light'" not in src, "the summary hardcodes the profile again"
    assert "'scanner_profile': getattr(config, 'profile'" in src


# -------------------------------------------------------------------- proxy
def test_no_proxy_configured_leaves_requests_alone(scanner):
    """None, not an empty dict. An empty proxies dict would SUPPRESS the HTTPS_PROXY /
    NO_PROXY handling requests does for free - which is the behaviour a customer whose
    environment is already set up is relying on."""
    proxies, verify = scanner._proxy_settings("", "")
    assert proxies is None
    assert verify is True


def test_an_explicit_proxy_covers_both_schemes(scanner):
    proxies, verify = scanner._proxy_settings("http://proxy.corp:8080", "")
    assert proxies == {"http": "http://proxy.corp:8080",
                       "https": "http://proxy.corp:8080"}
    assert verify is True


def test_a_ca_bundle_becomes_the_verify_target(scanner):
    """A TLS-terminating proxy presents its own certificate. Without its CA in the trust
    path every upload fails verification, and the error names TLS rather than the proxy."""
    _, verify = scanner._proxy_settings("http://proxy.corp:8080", "/etc/ssl/corp.pem")
    assert verify == "/etc/ssl/corp.pem"


def test_insecure_is_available_but_has_to_be_spelled_out(scanner):
    """A deliberate escape hatch, reachable only by typing the word - never by leaving a
    field blank - and announced on stderr on every run that uses it."""
    _, verify = scanner._proxy_settings("http://proxy.corp:8080", "insecure")
    assert verify is False


def test_every_outbound_call_carries_the_proxy_settings():
    """One missed call site is a scan that half-works behind a proxy: findings upload and the
    lifecycle row does not, or the reverse, and the scan reports success either way. Counted
    across the file rather than trusting that each site was edited."""
    src = open(_PY, encoding="utf-8").read()
    total = src.count("requests.post(")
    covered = src.count("proxies=_PROXIES, verify=_VERIFY")
    assert total > 0, "no outbound calls found - has the HTTP layer changed?"
    assert covered == total, (
        "%d of %d requests.post calls carry proxy settings" % (covered, total))


def test_the_insecure_warning_goes_to_stderr_not_stdout():
    """stdout is capped at 10,240 characters and that budget belongs to the SCAN_RESULT line
    the caller parses. A warning that crowds it out costs more than it explains."""
    src = open(_PY, encoding="utf-8").read()
    assert 'print(_msg, file=sys.stderr)' in src
