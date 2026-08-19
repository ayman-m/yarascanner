# Cancellation phase limit — evidence captured during Round 2, decides Round 3 criteria

Two legs isolate the boundary. The cancel MECHANISM works; its REACH is the gap.

| Leg | Target | Walk length | Cancel delivered | Outcome |
|---|---|---|---|---|
| C | `/usr`, non-matching rules | ~100s | 35s, inside the walk | **cancelled** at 57,527 of 93,127 files |
| B | 3,000 seeded files, flood rules | **8.8s** | 40s, after the walk | **ignored**; ran 212s more through delivery |

Leg B timeline, from its statistics log:

    05:48:37.124  scan starts
    05:48:45.922  "Target scan completed"   ->   walk =   8.8s
    05:52:17.930  "SCAN COMPLETED"          ->   run  = 220.8s

So 96% of that run was delivery. The cancel tool confirmed `scanner running: yes` when it
wrote the flag, and the run still finished with `outcome=completed`, `cancel_source=''`.

Cause: `cancel_requested` has exactly one polling reader, the walk loop
`while self.scan_active and not self.cancel_requested`. Once the walk exits, nothing polls
it, and the uploader drain runs to completion.

Whether this is a defect is a judgement call: draining to completion is what stops findings
being lost, and leg B's books stayed perfectly balanced (6,000 findings, 500 + 5,500
suppressed, 502 queued == 502 ok). But it is invisible to the operator, and on a
match-heavy scan the walk is a small fraction of wall-clock — so "cancel does nothing" is
the normal experience for exactly the scans someone would most want to stop.

This is a THIRD independent reason customers report that cancel does not work, alongside
the console Cancel hard-kill that orphans the lifecycle row.

Relevant Round 3 criteria: PERF-038 (cancel-flag watcher poll thread), PERF-039
(stack-driven cancellable walk), TRAV-019 (`_walk_cancellable`), LIFE-002 (cancel entry
point), LIFE-011 (mode=cancel short-circuit), DELI-037 (running.json liveness marker).

Leg C also showed honest shortfall reporting on a cancelled run:
`dataset rows: 1 of 2 NOT confirmed (1 never sent) - findings are complete in the local
logs on this endpoint`, with the books still balancing.
