# Release process

Internal. Not customer-facing.

## What a version means

Semantic versioning, from the customer's point of view — *"do I need to take this?"*

| Bump | When | Customer impact |
|---|---|---|
| **MAJOR** (3.0.0) | Something they rely on changes or is removed | Must read before upgrading |
| **MINOR** (2.1.0) | New capability, nothing existing breaks | Optional — take it if they want the feature |
| **PATCH** (2.0.1) | Fix, no behaviour they depend on changes | Take it |

A dataset schema change is **always** at least MINOR, and needs the `_v2` tag bumped —
`add_data` silently skips rows carrying fields the existing dataset does not know.

## The approval gate

**Never publish a release without asking first.** The judgement call is whether a change is
its own release or folds into the current one, and that decision is not the implementer's to
make. Prepare everything, then ask:

> *"Ready to release vX.Y.Z with <summary>. Separate release, or fold into the current one?"*

Only tag and publish after an explicit yes.

## Steps

1. **Land the work.** Tests green: `python3 -m pytest tests/ -q` (needs `psutil`,
   `requests`, `yara-python`). Run the config matrix in `local_test/cfgtest/` if any
   `CONFIG_*` constant changed.

2. **Bump the version** in `xdr_yara_scanner.py` — `__version__` and `__release_date__`, plus
   the `VERSION:` / `RELEASED:` lines and the capability list in the module docstring. Bump
   `__version__` in `xdr_data_management.py` if it shipped alongside.

3. **Write the release notes** in `CHANGELOG.md`. New section at the top. Cover:
   - **Upgrading** — what the customer must do. "Drop-in" is a valid and welcome answer.
   - **New / Changed / Fixed** — what changed and, briefly, *why it mattered*.
   - **Known limitations** — platform behaviours that will surprise them.

   This is the **only** place history lives. Measurements about a design we replaced, bugs we
   found, how we tested — all of it here, none of it in the guides.

4. **Re-stamp the guides.** Every doc in `docs/guides/` carries the version it describes:
   - `XDR_YARA_Scanner_Guide.md` — the `% Version` header line
   - `docs/guides/topics/*.md` — the *"Applies to scanner **vX.Y.Z**"* line

   Then re-read them against the diff. Guides describe the **current** version only: no "this
   used to work differently", no bug narratives, no test evidence except what proves a claim
   the current version makes.

5. **Check for customer-identifiable content** before anything is published — this repo is
   shared across customers:

   ```bash
   git ls-files | grep -vE "^local_test/" | xargs grep -rnoE \
     "api-[a-z0-9-]+\.xdr\.[a-z]+\.paloaltonetworks\.com|\b[0-9a-f]{32}\b" 2>/dev/null
   ```

   No tenant URLs, no real hostnames, no endpoint IDs, no keys. Placeholders only.

6. **Ask for approval.** See above. Stop here until you get it.

7. **Tag and publish:**

   ```bash
   git tag -a v2.0.0 -m "v2.0.0"
   git push origin v2.0.0
   gh release create v2.0.0 --title "v2.0.0" --notes-file <(sed -n '/^## v2.0.0/,/^## v[0-9]/p' CHANGELOG.md)
   ```

8. **Re-upload the script to the tenant's library.** The library copy is what customers
   actually run, and it does not update itself when the repo does.

## Giving a customer a version

Send them the tagged release, not the branch tip — `main` moves. The version is in the file
they receive, so a scan they run later can always be traced back to a known build.

When they report a problem, the first question is which version, and the answer is in
`scan_summary_<run_id>.json` under `scanner_version`.
