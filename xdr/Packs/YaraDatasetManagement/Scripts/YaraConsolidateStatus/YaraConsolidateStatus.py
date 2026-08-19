"""YaraConsolidateStatus — read-only readiness check for the YARA dataset merge.

Never writes or deletes anything (see YaraConsolidateCommon.check_consolidation_status).
Safe to call repeatedly, including from inside the playbook's wait/retry poll loop. The
playbook's condition task branches directly on the outputs this writes to context.
"""
import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403

from YaraConsolidateCommon import CoreApiClient, check_consolidation_status


def main():
    args = demisto.args()
    scan_ids = argToList(args.get("scan_id")) or None
    quiet_secs = args.get("quiet_secs")
    row_ceiling = args.get("row_ceiling")
    abandoned_after_hours = args.get("abandoned_after_hours")

    kwargs = {"only_scan_ids": scan_ids}
    if quiet_secs:
        kwargs["quiet_secs"] = int(quiet_secs)
    if row_ceiling:
        kwargs["row_ceiling"] = int(row_ceiling)
    if abandoned_after_hours:
        kwargs["abandoned_after_secs"] = int(float(abandoned_after_hours) * 3600)

    try:
        status = check_consolidation_status(CoreApiClient(), log=lambda *a: None, **kwargs)
    except Exception as ex:
        return_error("YaraConsolidateStatus failed: {}".format(ex))
        return

    lines = ["{} scan(s) eligible to consolidate".format(status["eligible_count"])]
    if status["any_in_progress"]:
        lines.append("{} scan(s) still in progress: {}".format(
            len(status["pending_scan_ids"]), ", ".join(status["pending_scan_ids"][:10])))
    if status["blocked_count"]:
        reasons = status.get("blocked_reasons", {})
        detail = ", ".join("{} ({})".format(sid, reasons.get(sid, "unknown"))
                           for sid in status["blocked_scan_ids"][:10])
        lines.append("{} scan(s) blocked: {}".format(status["blocked_count"], detail))

    # XSOAR merges (appends to) list-valued context by default across repeated calls to
    # the same investigation rather than replacing it - measured live: eligible_scan_ids
    # grew 72 -> 141 -> 177 across consecutive status checks on one issue, even though
    # each call's OWN return value was the correct, current set. Clear the path first so
    # every call leaves fresh, trustworthy context - a stale union here would make the
    # playbook's condition task and Apply's scan_id argument both read poisoned data.
    demisto.executeCommand("DeleteContext", {"key": "Yara.ConsolidateStatus"})

    return_results(CommandResults(
        readable_output="\n".join(lines),
        outputs_prefix="Yara.ConsolidateStatus",
        outputs=status,
        raw_response=status,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
