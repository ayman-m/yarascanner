"""YaraReport — read-only inventory of the tenant's YARA lookup datasets.

Never writes or deletes anything (see YaraConsolidateCommon.report_datasets, which issues
exactly one API call: the dataset listing). Safe to call repeatedly, including from inside
a poll loop, and safe to run concurrently with a consolidation or cleanup pass.

Deliberately does NOT write a row to yara_scanner_consolidation_runs: that dataset's schema
and status vocabulary describe a consolidation pass (consolidated_count / failed_scan_ids /
success|partial_failure|crashed), the Consolidation Run Health widget reads "a row in the
last ~24h" as proof the twice-daily merge Job completed, and rows from a read-only report
would both misreport those counts and mask a dead merge Job. It is also the whole point of
this automation that it writes nothing.
"""
import demistomock as demisto
from CommonServerPython import *  # noqa: F401,F403

from YaraConsolidateCommon import CoreApiClient, DEFAULT_SCHEMA_VERSION, report_datasets, set_schema_version


def main():
    args = demisto.args()
    try:
        # Always explicit, never inherited — see the same comment in YaraCleanup.main(): the
        # module global set_schema_version writes outlives a single automation execution in a
        # long-running XSOAR container.
        set_schema_version(args.get("schema_version") or DEFAULT_SCHEMA_VERSION)
    except Exception as ex:
        demisto.executeCommand("DeleteContext", {"key": "Yara.Report"})
        return_error("YaraReport: invalid argument ({}).".format(ex))
        return

    try:
        report = report_datasets(CoreApiClient())
    except Exception as ex:
        demisto.executeCommand("DeleteContext", {"key": "Yara.Report"})
        return_error("YaraReport failed: {}".format(ex))
        return

    lines = ["{} current-schema dataset(s), {} legacy, {} newer-schema (never pruned)".format(
        report["current_count"], report["legacy_count"], report["newer_count"])]
    if report["consolidated_count"]:
        lines.append("{} per-scan consolidated target(s) — consolidation OUTPUT, unrotated by "
                     "design, finished and not growing; never a cleanup candidate.".format(
                         report["consolidated_count"]))
    if report["frozen_count"]:
        lines.append("{} frozen (pre-rotation leftovers — rotation IS on for that host, "
                     "writes moved to the dated names; not growing): {}".format(
                         report["frozen_count"], ", ".join(report["frozen"])))
    if report["not_rotated_count"]:
        lines.append('{} NOT rotated — rotation is off for that deployment and these grow '
                     'without bound; set CONFIG_LOOKUP_ROTATION="monthly" in the scanner: '
                     '{}'.format(report["not_rotated_count"], ", ".join(report["not_rotated"])))
    # The rendered table is fixed-width; a code fence keeps the columns aligned in the War Room.
    lines += ["", "```", report["report"], "```"]

    # Same context-accumulation risk as YaraConsolidateStatus (see its comment) - XSOAR
    # appends to list-valued context across repeated calls in one investigation, so clear
    # the path first or `datasets`/`frozen`/`not_rotated` accumulate stale entries.
    demisto.executeCommand("DeleteContext", {"key": "Yara.Report"})

    return_results(CommandResults(
        readable_output="\n".join(lines),
        outputs_prefix="Yara.Report",
        outputs=report,
        raw_response=report,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
