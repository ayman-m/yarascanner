# Troubleshooting — XSIAM YARA Scanner

*Applies to scanner **v2.0.0**. History of changes: [release notes](../../CHANGELOG.md).*

Companion to the [XSIAM Deployment Guide](Deployment_Guide.md).

---

## Where to look first

Every scan writes to the scanner's `logs/` directory on the endpoint. Start with the scan
summary, then the error log, then the upload log.

## Common symptoms

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `yara_scans_raw` returns nothing | Token/endpoint wrong, or DNS/TLS blocked | Re-verify Step 3. From the endpoint, `curl <api-url>` should resolve. |
| Rows arrive but `rule_id`/`file_name` are null | Parsing rule not saved/disabled, or `target_dataset` typo | Confirm Step 2 — the `[INGEST: …]` header. |
| `Default YARA_RULE is empty` | First arg was empty | Always pass a base64 string in `yarafile`, or pre-populate the `YARA_RULE` constant. |
| `Base64 decode failed` | Pasted plain `.yar` text | Re-run the base64 step; strip trailing newlines. |
| `Scan failed: N rules failed compilation` | Bad YARA syntax in some rules | Check the `failed_rules/` directory on the endpoint; valid rules still ran. |
| Dashboards show zero on Windows | Agent has no embedded Python | Ensure the Cortex Agent Python add-on is present, or install `yara-python psutil requests`. |
| `WARNING: N upload operations failed` | Transient network / 5xx on the collector | The script retried; check collector status and re-run if the count is high. |
| Scan stuck > 6 h | Action Center timeout | Raise the script timeout (Step 4); the engine has no internal time cap. |
| macOS: many "Permission denied" | Not root / no Full Disk Access | Re-run elevated, or grant the Cortex Agent Full Disk Access in System Settings → Privacy. |

## Still stuck

Collect these before raising it:

1. The scan summary JSON from the endpoint
2. The error log for the same run
3. The agent version and OS of the affected endpoint
4. The rule file, if compilation is involved
