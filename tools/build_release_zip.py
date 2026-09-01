#!/usr/bin/env python3
"""Build the customer-facing release archives for YaraDatasetManagement.

Two artefacts, because the pack documents two delivery routes and they need different
shapes:

  YaraDatasetManagement-<ver>.zip          a content pack in the layout xsoar.pan.dev
                                           specifies - pack folder at zip root, only the
                                           directories the format allows. For a pack-zip
                                           install.
  YaraDatasetManagement-unified-<ver>.zip  the nine unified ymls on their own, for
                                           item-level import, which is the route that keeps
                                           items updatable afterwards.

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
# A filled-in URL or a long hex/base64 key where a placeholder belongs.
LEAK = re.compile(r'DEFAULT_XDR_API_(KEY|ID|URL)\s*=\s*"(?!replace_with_xdr)([^"]{4,})"')


def _keep(path):
    return not any(s in path for s in SKIP)


def _scan_for_credentials(paths):
    bad = []
    for p in paths:
        if not p.endswith((".yml", ".py", ".json", ".md")):
            continue
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for m in LEAK.finditer(text):
            bad.append("%s: DEFAULT_XDR_API_%s is filled in" % (os.path.relpath(p, REPO), m.group(1)))
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
