"""YaraCleanup — retention pruning for YARA lookup datasets. DELETES WHOLE DATASETS.

DRY RUN BY DEFAULT: without `execute=true` this reports what it WOULD delete and deletes
nothing, so an operator who runs it with no arguments can never lose data. The readable
output states which mode the run was in.

The seven safety rails live in YaraConsolidateCommon.prune_datasets and the functions it
calls (never the current month, never a future month, never an unsuffixed dataset, never a
newer schema version, never a name outside the yara_scanner_* contract, never a dataset
written to within min_quiet_hours, never a dataset still holding an unconsolidated scan).
They apply to BOTH selection paths — the retention window and delete_legacy — because
"legacy" is a classification derived from the schema_version argument, and a version set one
too high reclassifies the live tenant as legacy. A real deletion pass takes the same
consolidation lock YaraConsolidateApply uses, before the rails are evaluated; a dry run
never takes it.

Deliberately does NOT write a row to yara_scanner_consolidation_runs: that dataset's schema
is scan-oriented (consolidated_count, failed_scan_ids, status success|partial_failure|
crashed) and describes a consolidation pass. Recording dataset deletions there would
misreport counts on the Consolidation Run Health widget and — worse — a cleanup row would
satisfy that widget's "a row in the last ~24h" liveness check, masking a merge Job that has
stopped running. An executed prune instead writes one row to its own yara_scanner_cleanup_runs
dataset (see record_cleanup_run), because a War Room entry alone cannot answer "what did we
prune last month" for an action with no undo.
"""
import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403

from YaraConsolidateCommon import CoreApiClient, DEFAULT_MIN_QUIET_HOURS, DEFAULT_SCHEMA_VERSION
from YaraConsolidateCommon import MIN_ALLOWED_QUIET_HOURS, prune_datasets, set_schema_version


def _flag(args, name):
    """A boolean argument XSOAR may deliver as an absent key, an empty string, or a string.

    Absent/empty is False — that is what makes `execute` a dry run by default. Anything else
    goes through argToBoolean, so an unrecognised value RAISES rather than being quietly read
    as either truth value; main() turns that into a return_error naming the argument.
    """
    value = args.get(name)
    if value is None or value == "":
        return False
    return argToBoolean(value)


def main():
    args = demisto.args()
    notes = []

    # All argument coercion lives inside a try: on a destructive automation a mistyped
    # argument must produce this script's own message ("nothing was deleted"), not a raw
    # traceback that leaves the operator guessing which argument was rejected.
    try:
        # Always set the version explicitly, even when the caller passed none. An XSOAR docker
        # image serves many executions from one process, and set_schema_version mutates a
        # module global plus os.environ — without this reset a run that passed schema_version
        # would silently decide the scope of the NEXT run that passed none.
        set_schema_version(args.get("schema_version") or DEFAULT_SCHEMA_VERSION)

        older_than_months = args.get("older_than_months")
        older_than_months = int(older_than_months) if older_than_months not in (None, "") else None
        if older_than_months is not None and older_than_months < 0:
            notes.append("older_than_months was negative ({}); clamped to 0. A negative window "
                         "means nothing beyond 0 (\"every month before the current one\") and "
                         "would leave rails 1 and 2 as the only thing standing between the "
                         "prune and a live shard.".format(args.get("older_than_months")))
            older_than_months = 0

        min_quiet_hours = args.get("min_quiet_hours")
        min_quiet_hours = (float(min_quiet_hours) if min_quiet_hours not in (None, "")
                           else DEFAULT_MIN_QUIET_HOURS)
        if min_quiet_hours < MIN_ALLOWED_QUIET_HOURS:
            # 0 (or a negative) does not relax rail 6, it switches it off entirely: the
            # comparison `(now - newest) < 0` is false even for a row written a second ago.
            notes.append("min_quiet_hours was {} — below the {}h floor, which would DISABLE the "
                         "recency rail rather than relax it. Raised to {}h for this run."
                         .format(args.get("min_quiet_hours"), MIN_ALLOWED_QUIET_HOURS,
                                 MIN_ALLOWED_QUIET_HOURS))
            min_quiet_hours = MIN_ALLOWED_QUIET_HOURS

        kwargs = {
            "older_than_months": older_than_months,
            "delete_legacy": _flag(args, "delete_legacy"),
            "min_quiet_hours": min_quiet_hours,
            "force": _flag(args, "force"),
            # The opt-in. Absent -> False -> dry run: nothing is deleted.
            "execute": _flag(args, "execute"),
        }
    except Exception as ex:
        # Context is cleared on the failure path too: a crashed destructive run must not leave
        # a PREVIOUS run's Yara.Cleanup.deleted list in context for a downstream task to read
        # as this run's outcome.
        demisto.executeCommand("DeleteContext", {"key": "Yara.Cleanup"})
        return_error("YaraCleanup: invalid argument ({}). Nothing was deleted.".format(ex))
        return

    log_lines = []
    try:
        result = prune_datasets(CoreApiClient(), log=lambda m: log_lines.append(m), **kwargs)
    except Exception as ex:
        demisto.executeCommand("DeleteContext", {"key": "Yara.Cleanup"})
        return_error("YaraCleanup failed: {}".format(ex))
        return

    if result["nothing_requested"]:
        lines = ["Nothing selected and nothing deleted: no retention window was given "
                 "(older_than_months) and delete_legacy is false. This automation has no "
                 "default window on purpose — a bare invocation must never delete."]
    elif result["lock_held_by_other_run"]:
        lines = ["Skipped this pass — the consolidation lock is held by another concurrent "
                 "run (YaraConsolidateApply, the CLI, or another Job execution). Nothing "
                 "was deleted. Pruning and consolidation mutate the same shards, so this "
                 "run stands down rather than race it."]
    elif result["dry_run"]:
        lines = ["DRY RUN — nothing was deleted. {} dataset(s) WOULD be deleted; re-run with "
                 "execute=true to apply.".format(result["selected_count"])]
        lines += ["  would delete  {}".format(n) for n in result["selected"]]
    else:
        lines = ["EXECUTED — {} dataset(s) deleted, {} failed.".format(
            result["deleted_count"], result["failed_count"])]
        lines += ["  deleted  {}".format(n) for n in result["deleted"]]
        lines += ["  FAILED   {}: {}".format(f["dataset"], f["error"]) for f in result["failed"]]

    # The scope this run actually ran with. schema_version decides whether the run had any
    # scope at all, and min_quiet_hours is rail 6's threshold — both belong in the record.
    lines.append("scope: schema v{}, window={}, delete_legacy={}, min_quiet_hours={}".format(
        result["schema_version"],
        "none" if result["older_than_months"] is None else result["older_than_months"],
        result["delete_legacy"], result["min_quiet_hours"]))
    lines += ["NOTE: {}".format(n) for n in notes]

    if result.get("lock_taken_over"):
        lines.append("WARNING: another run's consolidation lock marker was present and this "
                     "pass TOOK IT OVER as stale ({}). If a consolidation pass was in fact "
                     "still running, its shards were pruned concurrently."
                     .format(result.get("lock_takeover_reason", "")))

    # Every skipped candidate's reason, in full and uncapped: a dataset silently not deleted
    # is indistinguishable from a bug, and this entry is the run's audit trail.
    if result["skipped"]:
        lines.append("")
        lines.append("{} candidate(s) kept, with reason:".format(result["skipped_count"]))
        lines += ["  skip  {}".format(s) for s in result["skipped"]]

    # Lock events (takeover, failed release) exist ONLY in the library's log, not in the
    # structured result — and on this automation they are the difference between a routine
    # pass and one that ran alongside a consolidation.
    lock_log = [m for m in log_lines if "lock" in m.lower()]
    if lock_log:
        lines.append("")
        lines.append("lock events:")
        lines += ["  {}".format(m) for m in lock_log]

    # Same context-accumulation risk as YaraConsolidateStatus (see its comment) - clear
    # before writing so selected/deleted/skipped never carry entries from a prior call.
    demisto.executeCommand("DeleteContext", {"key": "Yara.Cleanup"})

    return_results(CommandResults(
        readable_output="\n".join(lines),
        outputs_prefix="Yara.Cleanup",
        outputs=result,
        raw_response=result,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
