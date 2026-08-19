"""YaraConsolidateApply — perform the actual per-scan dataset merge.

Mutating: creates per-scan target datasets, writes rows, deletes fully-verified
source shards (see YaraConsolidateCommon.consolidate_all / run_consolidation).
Internally idempotent per scan (an already-complete target is verified, not
rewritten), so a duplicate invocation cannot double-write — but it still re-reads
tenant-wide state each call, so it is not free. The playbook should call this once
per pass, not speculatively.
"""
import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403

from YaraConsolidateCommon import CoreApiClient, consolidate_all, record_consolidation_run


def main():
    args = demisto.args()
    scan_ids = argToList(args.get("scan_id")) or None
    quiet_secs = args.get("quiet_secs")
    row_ceiling = args.get("row_ceiling")
    abandoned_after_hours = args.get("abandoned_after_hours")

    kwargs = {"only_scan_ids": scan_ids, "dry_run": False}
    if quiet_secs:
        kwargs["quiet_secs"] = int(quiet_secs)
    if row_ceiling:
        kwargs["row_ceiling"] = int(row_ceiling)
    if abandoned_after_hours:
        kwargs["abandoned_after_secs"] = int(float(abandoned_after_hours) * 3600)

    log_lines = []
    client = None
    try:
        client = CoreApiClient()
        result = consolidate_all(client, log=lambda m: log_lines.append(m), **kwargs)
    except Exception as ex:
        # Record the crash as a queryable row (best-effort — see record_consolidation_run)
        # BEFORE calling return_error, since return_error halts this task and the playbook's
        # own Task 8 "needs attention" flag is never reached from here (edge case #36/#53:
        # a total execution crash is exactly the failure mode Task 8 cannot record). Only
        # possible if CoreApiClient() itself constructed successfully — if credentials are
        # still placeholders, client is None and there is nothing to write with.
        if client is not None:
            record_consolidation_run(client, "crashed", error_message=str(ex), log=lambda *a: None)
        return_error("YaraConsolidateApply failed: {}".format(ex))
        return

    record_consolidation_run(
        client, "partial_failure" if result["failed_count"] else "success",
        result=result, log=lambda *a: None)

    if result.get("lock_held_by_other_run"):
        lines = ["Skipped this pass — consolidation lock is held by another concurrent run "
                 "(CLI or another Job execution)."]
    else:
        lines = ["{} scan(s) consolidated".format(result["consolidated_count"])]
        if result["deferred_count"]:
            lines.append("{} scan(s) deferred (became active mid-run): {}".format(
                result["deferred_count"], ", ".join(result["deferred_scan_ids"][:10])))
        if result["failed_count"]:
            reasons = result.get("failed_reasons", {})
            detail = ", ".join("{} ({})".format(sid, reasons.get(sid, "unknown"))
                               for sid in result["failed_scan_ids"][:10])
            lines.append("{} scan(s) FAILED — needs attention: {}".format(result["failed_count"], detail))

    # Lock events exist ONLY in the library's log stream, never in the structured result:
    # acquire_consolidation_lock's "stale or unreadable — taking over" (which precedes
    # force-deleting another run's marker) and release_consolidation_lock's "could not
    # release" (which parks every following pass until the marker goes stale). Both are
    # otherwise invisible to the operator.
    lock_log = [m for m in log_lines if "lock" in m.lower()]
    if lock_log:
        lines.append("")
        lines.append("lock events:")
        lines += ["  {}".format(m) for m in lock_log]

    # Same context-accumulation risk as YaraConsolidateStatus (see its comment) - clear
    # before writing so consolidated/deferred/failed lists never carry stale entries from
    # a prior call to the same investigation.
    demisto.executeCommand("DeleteContext", {"key": "Yara.ConsolidateApply"})

    return_results(CommandResults(
        readable_output="\n".join(lines),
        outputs_prefix="Yara.ConsolidateApply",
        outputs=result,
        raw_response=result,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
