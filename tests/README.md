# YARA Scanner — Test Suite

The dual-edition pytest regression suite. Most files exercise **both** `xdr_yara_scanner.py`
and `xsiam_yara_scanner.py` from a shared `EDITIONS` list — the mechanism that stops the two
scanners drifting apart. See the root [README.md](../README.md#running-the-tests) for how to
run the full suite.

## Layout

- `test_*.py` — the regression suite, one file (or group of files) per behavior area.
- `throttle/test_cpu_governor.py` — pytest, no network: target computation per policy, the
  `cpu_percent ÷ cpu_count` normalisation, ratio clamping, pacing, migration shim.
  Run: `pytest tests/throttle/ -q`
- `secrets_white_list.json` — required by the pack-validation tooling that checks
  `xdr/Packs/YaraDatasetManagement/`.
