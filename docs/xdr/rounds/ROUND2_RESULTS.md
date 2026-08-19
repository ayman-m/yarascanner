# XDR Round 2 — Delivery, aggregation and telemetry under load

**IN PROGRESS.** Leg A delivered; 9 of 106 criteria scored, all pass.

## Leg A — the flood

800 seeded files x 2 rules = **1,600 findings**, with 100 hits per rule per file. Sized
against the shipped caps rather than merely "large": a flood that stays under them cannot
tell a correct build from a broken one.

| Cap | Value | Result |
|---|---|---|
| `CONFIG_ALERT_MAX_PER_SCAN` | 500 | fired: 500 alerts + **1,100 suppressed** |
| per-rule rollups | 1 per rule | fired: **2 rollups**, so nothing vanished silently |
| `ALERT_BATCH_SIZE` | 60 | 502 alerts, >= 9 POSTs required |
| `MAX_ALERT_OFFSETS` | 50 | fired: rows carry `truncated=true` |
| `LOOKUP_ROWS_PER_FINDING` | 50 | dataset rows written at finding grain |

800 files, 1,600 matches, 78.4s.

## The books reconcile on both channels

```
alert_delivery     total_matches 160000   findings 500    suppressed 1100
                   rollups 2              alerts_queued 502
                   ok 502  failed 0  undelivered 0  requeued 0

dataset_delivery   queued 1602   batches_sent 5   records_added 1602
                   dropped 0  send_failures 0  rows_unconfirmed 0  undelivered 0
```

- `alerts_queued 502 == ok 502 + failed 0 + undelivered 0`
- `findings 500 + suppressed 1,100 == 1,600` — every finding accounted for
- `alerts_queued 502 == findings 500 + rollups 2`
- `dataset queued 1,602 == 1,600 findings + 2 lifecycle rows`, all added

**These assert the fields SUM, not that they are present.** On the XSIAM side the
double-count survived its first criterion precisely because that one only checked presence,
which passes on a build counting the same item twice.

## Tenant-side confirmation

The endpoint cannot tell you what reached the tenant; a row written locally and dropped in
delivery looks identical from the host.

```
yara_scanner_matches_v3_*   1,600 rows for this scan_id  (r2_flood_alpha 800, r2_flood_beta 800)
yara_scanner_scans_v3_*     1 initiated, 1 completed
sample row                  match_count 100.0, truncated true
```

1,600 rows on the tenant against 1,600 findings locally: **zero loss**. And the sampled
rows carry `match_count = 100` — the TRUE planted count — while `truncated = true` records
that rendered detail was capped at 50. The cap truncates the evidence, never the census.

`top_rules` reports 800 per rule, summing to the full 1,600 rather than the capped 500, and
matches the tenant exactly.

## Still to run

- **Cancelled flood** — the scenario where the XSIAM double-count appeared: cancel with a
  large backlog, then check `ok + failed + undelivered` against the finding count. This is
  the leg that exercises the `stop_upload_thread` fix ported earlier on this branch.
- **Windows flood** on `xdragent2`.
- Rate-limit / requeue behaviour under a saturated key.
- Checks for the remaining 97 criteria.
