# Consolidation cannot reduce dataset count, and makes retention worse

**Status: confirmed.** Found 2026-08-20 during Round 5 preparation, then survived four
independent attempts to refute it. This is an origin defect, not a regression.

## The claim

Under the shipped scanner, consolidation cannot reduce the number of lookup datasets. For a
repeatedly-scanned host it increases them, and the datasets it creates are unprunable, so it
is strictly worse than not running it.

## Why

Two pure functions disagree about what "a scan" is.

```
scan_id     = f"{hostname}_{run_id}_yara_{rule_hash[:12]}"    xdr_yara_scanner.py:2988
              run_id is a per-process microsecond timestamp    :2864
              no env var and no option key overrides it        _VALID_OPTION_KEYS :901-904

shard name  = <host>_<hash6>[_<YYYYMM>]                        no scan component
```

`scan_id` is a function of (hostname, run_id, rule-hash); the shard name is a function of
(hostname, month). So **every scan_id's rows of one kind live in exactly one shard — the
fan-in factor is identically 1.** Therefore `targets = |scan_ids| >= |shards|`, with equality
only when each shard holds exactly one scan. Never a reduction; strictly one extra pair per
re-scan within a month.

Measured against the real `xdr_consolidate` and the real `FakeClient`:

| Scenario | before -> after |
|---|---|
| 2 hosts, one campaign | 4 shards -> 4 targets (2 plans, 1 source each) |
| 1 host x 3 scans | 2 shards -> 6 targets |
| 20 hosts, one campaign | 40 shards -> 40 targets |
| **control:** 20 hosts, shared rule-hash scan_id | 40 shards -> **2 targets** |

The control matters: the fan-in machinery is correct and folds 40 into 2 when handed a
shared `scan_id`. It has nothing to fan in.

## It is worse than count-neutral

Per-scan targets are **excluded from retention** (`xdr_data_management.py:137-141`, and again
on the legacy path at `:302-305`), on the reasoning that after the source shards are deleted
the target is the only copy of that scan. Verified by running the real selector: given one
month-suffixed shard and one per-scan target, the **shard is deletable and the target is
skipped**.

So consolidation converts a *prunable, month-suffixed, steady-state* population into an
*immortal, unprunable, monotonically growing* one — at equal instantaneous count. At 50k
hosts on a monthly cadence with a 6-month window, the crossover where consolidation is
strictly losing arrives around month 8.

On this two-host lab the effect is small but perverse: each scan of each host leaves 2
permanent datasets. Ten test scans across both hosts leaves 40 that no automated path will
ever delete. **The lab accumulates clutter in proportion to how much we test**, which is the
opposite of what the tool advertises.

## The purpose really is count reduction

Not an alternative reading that 1:1 merges would satisfy:

- `xdr_consolidate.py:12` — "so the tenant's dataset count is bounded by scans, not hosts"
- `Datasets_and_Maintenance.md:182` — "Consolidation only reduces how many datasets exist."

"Bounded by scans, not hosts" is true and vacuous, because scans >= hosts always.

## Root cause

The v4 change deliberately abolished the fleet-wide rule-hash `scan_id` because it "broke
multi-host correlation in XDR" (`:2982-2987`). The CHANGELOG records it as a breaking change
and audits the blast radius as "No shipped widget or dashboard uses `scan_id`" — an audit
that checked widgets and dashboards and never checked `group_shards_by_scan`, whose only
merge axis it had just removed. Consolidation landed a month later against a scanner that
already emitted host-scoped ids.

## Why no test caught it

Every consolidation fixture uses synthetic shared scan_ids (`"S1"`..`"S9"`, 149+ occurrences
in `tests/test_consolidation.py`); zero real-shaped scan_ids anywhere under `tests/`. With a
shared id the merge genuinely is many-to-one, so 74 pre-existing tests, 7 files added in
Round 4, and all seven mutation waves were consistent with a premise the product does not
satisfy.

`xdr/simulation/` does use realistic host-scoped ids (`simlib.new_scan_id`) but imports
nothing from `xdr_consolidate`. The fixtures exercised the logic with unrealistic ids; the
simulation exercised realistic ids against the API primitives. The two halves never met.

## Known exceptions

- A tenant carrying **pre-v4 history** does fan in — those rows share a rule-hash scan_id.
- A run straddling a monthly rotation boundary is 2 -> 1.

## Candidate fixes

**(a) Shared campaign id injected at delivery.** Do *not* revert `scan_id`; per-run
uniqueness is load-bearing for multi-host correlation. Add a separate `campaign_id` column
populated from a new option key, generated once per Action Center action, defaulting to
`scan_id` when absent so ad-hoc runs keep today's behaviour. Consolidation groups and names
on it. Costs a schema bump and a rollout window where mixed fleets produce both grains.

**(b) Key on `(rule_hash12, scan_date)`.** Consolidation-only; no scanner, schema or endpoint
change. The hash is already recoverable from `scan_id` and `scan_date` is already a schema
column. Restores real fan-in immediately. Costs: two unrelated campaigns sharing a ruleset on
one day merge silently, and a campaign crossing midnight splits in two.

**(c) Accept 1:1 and fix retention instead** — make per-scan targets prunable. Removes the
harm but abandons the stated purpose.

**(d) Do nothing** — but then stop running consolidation, because it currently trades
prunable datasets for unprunable ones at no benefit.

## Operational consequence, immediately

**Do not run `xdr_data_management.py --consolidate --yes` against the tenant**, and do not
run Round 5's apply steps, until this is decided. Dry runs (no `--yes`) are safe and
informative. Every applied consolidation creates permanent datasets that no automated path
will remove.
