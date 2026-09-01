#!/usr/bin/env python3
"""The runtime profile and the proxy settings - both CONFIG constants, not scan arguments.

The profile existed in name only. `light_profile` was hardcoded True and read nowhere, the
startup log announced "Light profile active: reduced workers, reduced monitoring" on every
run, and the scan summary reported `scanner_profile: 'light'` unconditionally. None of it
changed behaviour, so a report saying "light profile" described a setting that did not exist
- worse than saying nothing, because it is checkable and wrong.

Proxy support did not exist. An endpoint that must egress through a proxy had no way to say
so: requests honours HTTPS_PROXY only when the process environment carries it, and an Action
Center script's does not - it is handed three inputs and no environment.

Both are deliberately CONFIG-only. They describe the environment a fleet runs in rather than
anything about a particular scan, so they are edited once in the script; the Action Center
inputs stay yarafile / scan_folder / alert_severity.
"""
import base64
import importlib.util
import os
import re
import tempfile

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PY = os.path.join(_REPO, "xdr", "xdr_yara_scanner.py")
_RULES = base64.b64encode(b"rule T {\n  condition:\n    false\n}\n").decode()


def _load():
    """Fresh import each time: the profile is read at ScanConfig construction from an env var
    these tests set, and a cached module would carry the previous value."""
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
    afterwards, and a scan is not frequent enough for the sampling thread to be worth
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
    """It never did, whatever the old startup message claimed. Worker count and CPU impact
    are CONFIG_WORKERS and the CPU governor and apply to both profiles - so someone choosing
    `light` expecting a gentler scan must be told, not quietly given the same one."""
    plain = _cfg(_load())
    monkeypatch.setenv("YARA_PROFILE", "light")
    light = _cfg(_load())
    assert light.max_workers == plain.max_workers
    assert light.cpu_guarantee == plain.cpu_guarantee


def test_an_unknown_profile_is_rejected_not_guessed(monkeypatch):
    """Two values, no near-misses worth guessing between."""
    monkeypatch.setenv("YARA_PROFILE", "medium")
    with pytest.raises(ValueError, match="full.*light"):
        _cfg(_load())


def test_the_summary_reports_the_profile_that_actually_ran():
    """It was hardcoded to 'light' regardless, so the one field telling an operator which
    profile ran always said the same thing."""
    src = open(_PY, encoding="utf-8").read()
    assert "'scanner_profile': 'light'" not in src, "the summary hardcodes the profile again"
    assert "'scanner_profile': getattr(config, 'profile'" in src


# -------------------------------------------------------------------- proxy
def test_no_proxy_configured_leaves_requests_alone(scanner):
    """None, not an empty dict. An empty proxies dict SUPPRESSES the HTTPS_PROXY / NO_PROXY
    handling requests does for free, which is not the same thing as "no proxy set" and is
    the behaviour a customer with a configured environment already relies on."""
    scanner.CONFIG_PROXY = ""
    proxies, _ = scanner._proxy_settings()
    assert proxies is None


def test_an_explicit_proxy_covers_both_schemes(scanner):
    scanner.CONFIG_PROXY = "http://proxy.corp:8080"
    proxies, _ = scanner._proxy_settings()
    assert proxies == {"http": "http://proxy.corp:8080",
                       "https": "http://proxy.corp:8080"}


def test_uploads_are_not_broken_by_an_untrusted_root_ca(scanner):
    """The reason verification is off by default.

    A TLS-intercepting proxy presents its own certificate, which cannot validate against the
    public roots. With verification on and that CA absent from the endpoint's trust store,
    EVERY call to the tenant fails - and it fails at the transport, so a scan runs to
    completion locally and delivers nothing. Off, the upload succeeds.
    """
    assert scanner.CONFIG_VERIFY_TLS is False, (
        "verification is on by default again - an untrusted intercepting proxy will now "
        "break every upload rather than merely being unauthenticated")
    _, verify = scanner._proxy_settings()
    assert verify is False


def test_tls_verification_follows_its_own_constant(scanner):
    """One switch decides it, and there is no CA-bundle path to get wrong: a TLS-intercepting
    proxy needs no configuration on the endpoint at all. Turning it back on is a one-line
    edit for a network where the path is not trusted."""
    scanner.CONFIG_VERIFY_TLS = False
    assert scanner._proxy_settings()[1] is False
    scanner.CONFIG_VERIFY_TLS = True
    assert scanner._proxy_settings()[1] is True


def test_verification_off_is_announced_and_not_left_to_library_noise():
    """The posture must never be silent. requests warns once per session into logs nobody
    reads; the scanner states it on stderr on every run and suppresses the library warning."""
    src = open(_PY, encoding="utf-8").read()
    assert "TLS verification is OFF" in src
    assert "disable_warnings" in src, "urllib3 InsecureRequestWarning is not suppressed"


def test_every_outbound_call_carries_the_proxy_settings():
    """One missed call site is a scan that half-works behind a proxy - findings upload and
    the lifecycle row does not, or the reverse - and it reports success either way. Counted
    across the file rather than trusting each site was edited."""
    src = open(_PY, encoding="utf-8").read()
    total = src.count("requests.post(")
    covered = src.count("proxies=_PROXIES, verify=_VERIFY")
    assert total > 0, "no outbound calls found - has the HTTP layer changed?"
    assert covered == total, (
        "%d of %d requests.post calls carry proxy settings" % (covered, total))


def test_the_tls_notice_goes_to_stderr_not_stdout():
    """stdout is capped at 10,240 characters and that budget belongs to the SCAN_RESULT line
    the caller parses. A notice that crowds it out costs more than it explains."""
    src = open(_PY, encoding="utf-8").read()
    assert "print(_msg, file=sys.stderr)" in src


# ------------------------------------------------- config, not scan arguments
def test_environment_settings_are_not_scan_options():
    """Proxy, TLS and profile describe where the fleet runs, not what one scan does.
    Threading them through every dispatch would mean every caller had to know the network
    layout."""
    src = open(_PY, encoding="utf-8").read()
    keys = re.search(r"_VALID_OPTION_KEYS = \{(.*?)\}", src, re.S).group(1)
    for leaked in ("proxy", "proxy_ca_bundle", "profile",
                   "enable_perf_monitor", "enable_resource_monitor", "enable_fd_monitor"):
        assert '"%s"' % leaked not in keys, "%s became a scan option" % leaked


def test_the_action_center_input_list_is_unchanged():
    """Three inputs, in this order. core-script-run rejects any parameter set that does not
    exactly match the script's declared inputs, so adding one silently breaks every existing
    dispatch and every playbook that builds one."""
    src = open(_PY, encoding="utf-8").read()
    assert 'def main(yarafile=None, scan_folder=None, alert_severity="low"):' in src
