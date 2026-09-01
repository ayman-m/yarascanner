#!/usr/bin/env python3
"""Build the customer-facing release archives for YaraDatasetManagement.

Two artefacts, because the pack documents two delivery routes and they need different
shapes:

  YaraDatasetManagement-<ver>.zip          a content pack in the layout xsoar.pan.dev
                                           specifies - pack folder at zip root, only the
                                           directories the format allows. For a pack-zip
                                           install. All three playbooks and all nine
                                           automations.
  YaraDatasetManagement-unified-<ver>.zip  the nine unified ymls on their own, for
                                           item-level import, which is the route that keeps
                                           items updatable afterwards.
  yarascanner-xdr-<ver>.zip                EVERYTHING a customer needs for Cortex XDR: the
                                           pack above, plus the endpoint scanner and the
                                           local toolkit, which are not XSOAR content and
                                           have no directory in the pack format.

The scanner is the reason the third archive exists. xdr_yara_scanner.py runs ON AN ENDPOINT
via the Action Center script library - it is not an automation, not a playbook, and there is
no content-pack directory that means "Action Center script". Putting it inside the pack
folder would either be ignored by a pack install or break it. So the pack stays exactly to
spec, and the complete bundle carries both halves side by side.

`unified/` is deliberately NOT in the pack zip: it is this project's own delivery
convention, not one of the directories the pack format defines, and a zip-install has no
use for it.

REFUSES TO BUILD if any file carries something that looks like a real credential. A filled-in
copy is what runs on a tenant and must never be what a customer downloads - the shipped files
are supposed to carry `replace_with_xdr_*` placeholders for the operator to complete.
"""
import json
import os
import re
import sys
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK = os.path.join(REPO, "xdr", "Packs", "YaraDatasetManagement")
OUT = os.path.join(REPO, "dist")

# Directories the content-pack format defines. Anything else stays out of the pack zip.
PACK_DIRS = ("Integrations", "Scripts", "Playbooks", "Reports", "Dashboards", "IncidentTypes",
             "IncidentFields", "Layouts", "Classifiers", "IndicatorTypes", "IndicatorFields",
             "Connections", "TestPlaybooks")
PACK_FILES = ("pack_metadata.json", "README.md", "CHANGELOG.md", ".secrets-ignore",
              ".pack-ignore", "Author_image.png", "CONTRIBUTORS.json")
SKIP = ("__pycache__", ".DS_Store", ".pyc")

PLACEHOLDERS = ("replace_with_xdr_advanced_api_key", "replace_with_xdr_advanced_api_id",
                "replace_with_xdr_api_url")
# Content files must carry the placeholder. Prose may use its own examples ("your-api-key"),
# so this pattern is applied ONLY to .py/.yml under the pack, never to documentation.
FILLED = re.compile(r'DEFAULT_XDR_API_(KEY|ID|URL)\s*=\s*"(?!replace_with_xdr)([^"]{4,})"')


def _live_secrets():
    """The actual values from .env. A shipped file containing one of these is the leak that
    matters - far more precise than guessing which strings look secret."""
    out = {}
    env = os.path.join(REPO, ".env")
    if not os.path.exists(env):
        return out
    for line in open(env):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            if k.strip() in ("XDR_API_KEY", "XDR_API_ID", "XDR_API_URL") and len(v) >= 8:
                out[k.strip()] = v
    return out


def _keep(path):
    return not any(s in path for s in SKIP)


def _scan_for_credentials(paths, strict_placeholder=True):
    """Two checks, different scopes.

    1. No shipped file may contain a value that is actually in .env. This is the real leak
       test and it applies to everything, prose included.
    2. Pack content (.py/.yml) must additionally still carry the replace_with_xdr_*
       placeholder, so a customer knows to fill it in. Documentation is exempt - a guide
       showing `DEFAULT_XDR_API_KEY = "your-api-key"` is doing its job, and flagging it
       taught nothing except to distrust the check.
    """
    live = _live_secrets()
    bad = []
    for p in paths:
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for name, value in live.items():
            if value in text:
                bad.append("%s: contains the LIVE %s from .env" % (os.path.relpath(p, REPO), name))
        if strict_placeholder and p.endswith((".yml", ".py")):
            for m in FILLED.finditer(text):
                bad.append("%s: DEFAULT_XDR_API_%s is filled in, expected a placeholder"
                           % (os.path.relpath(p, REPO), m.group(1)))
    return bad


def collect_pack():
    files = []
    for name in PACK_FILES:
        p = os.path.join(PACK, name)
        if os.path.exists(p):
            files.append(p)
    for d in PACK_DIRS:
        root = os.path.join(PACK, d)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [x for x in dirnames if _keep(x)]
            files += [os.path.join(dirpath, f) for f in filenames if _keep(f)]
    return sorted(files)


# Not XSOAR content, but part of the XDR deliverable.
EXTRAS = [
    ("ActionCenter/xdr_yara_scanner.py", os.path.join(REPO, "xdr", "xdr_yara_scanner.py")),
    ("tools/xdr_action_center.py",       os.path.join(REPO, "xdr", "xdr_action_center.py")),
    ("docs/Deployment_Guide.md",         os.path.join(REPO, "xdr", "docs", "Deployment_Guide.md")),
    ("docs/Manual_Validation_Runbook.md", os.path.join(REPO, "xdr", "docs", "Manual_Validation_Runbook.md")),
    ("docs/Troubleshooting.md",          os.path.join(REPO, "xdr", "docs", "Troubleshooting.md")),
]

BUNDLE_README = """YARA Scanner for Cortex XDR - complete bundle
=============================================

Two halves, delivered together because they are useless apart.

  YaraDatasetManagement/     The XSOAR content pack: 9 automations, 3 playbooks.
                             Import this into Cortex. Either install the whole pack,
                             or import the automations individually - pick ONE and
                             stay with it, because a pack install marks every item
                             system-owned and item-level updates are refused after
                             that.

                             SEVEN of the nine automations ship with
                             replace_with_xdr_* placeholders. Fill them in BEFORE
                             importing; an automation imported with placeholders
                             fails at its first call. The two rules automations make
                             no API call and need nothing.

  ActionCenter/              xdr_yara_scanner.py - the scanner itself. This does NOT
                             go into Cortex content. Upload it to the Action Center
                             script library, declaring exactly three string inputs,
                             in this order: yarafile, scan_folder, alert_severity.
                             Entry point: main. Windows, Linux and macOS.

  tools/                     xdr_action_center.py - optional local CLI for driving
                             scans and querying datasets from a shell. Not deployed
                             anywhere.

  docs/                      Deployment guide, validation runbook, troubleshooting.

Order: upload the scanner, import the pack, fill in credentials, then run
YaraReport to confirm the round trip. On a tenant that has never scanned, zero
datasets is a pass.
"""


def main():
    version = json.load(open(os.path.join(PACK, "pack_metadata.json")))["currentVersion"]
    os.makedirs(OUT, exist_ok=True)
    pack_files = collect_pack()
    unified = sorted(os.path.join(PACK, "unified", f)
                     for f in os.listdir(os.path.join(PACK, "unified")) if f.endswith(".yml"))

    leaks = _scan_for_credentials(pack_files + unified)
    if leaks:
        print("REFUSING TO BUILD - real credentials found in files bound for a release:")
        for l in leaks:
            print("   ", l)
        print("\nThe shipped copies must carry replace_with_xdr_* placeholders.")
        return 1

    pack_zip = os.path.join(OUT, "YaraDatasetManagement-%s.zip" % version)
    with zipfile.ZipFile(pack_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for f in pack_files:
            z.write(f, os.path.join("YaraDatasetManagement", os.path.relpath(f, PACK)))
    print("pack archive : %s  (%d files, %.1f KB)"
          % (os.path.basename(pack_zip), len(pack_files), os.path.getsize(pack_zip) / 1024.0))

    uni_zip = os.path.join(OUT, "YaraDatasetManagement-unified-%s.zip" % version)
    with zipfile.ZipFile(uni_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for f in unified:
            z.write(f, os.path.join("unified", os.path.basename(f)))
    print("unified bundle: %s  (%d ymls, %.1f KB)"
          % (os.path.basename(uni_zip), len(unified), os.path.getsize(uni_zip) / 1024.0))

    # Every credentialed automation must still ASK for a key, or the customer will not know to
    # supply one and will hit a 401 at first run instead.
    need = [f for f in unified
            if "DEFAULT_XDR_API_KEY" in open(f, encoding="utf-8", errors="replace").read()]
    ok = [f for f in need
          if all(p in open(f, encoding="utf-8", errors="replace").read() for p in PLACEHOLDERS)]
    print("credentialed automations: %d, all carrying placeholders: %s" % (len(need), len(ok) == len(need)))

    missing = [src for _, src in EXTRAS if not os.path.exists(src)]
    if missing:
        print("REFUSING - bundle inputs missing:", missing)
        return 1
    # Docs legitimately show example values; only the live-secret check applies to them.
    extra_leaks = _scan_for_credentials([src for _, src in EXTRAS],
                                        strict_placeholder=False)
    if extra_leaks:
        print("REFUSING - real credentials in bundle inputs:")
        for l in extra_leaks:
            print("   ", l)
        return 1

    bundle = os.path.join(OUT, "yarascanner-xdr-%s.zip" % version)
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        for f in pack_files:
            z.write(f, os.path.join("YaraDatasetManagement", os.path.relpath(f, PACK)))
        for arc, src in EXTRAS:
            z.write(src, arc)
        z.writestr("README-FIRST.txt", BUNDLE_README)
    print("complete bundle: %s  (%d files, %.1f KB)"
          % (os.path.basename(bundle), len(pack_files) + len(EXTRAS) + 1,
             os.path.getsize(bundle) / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
