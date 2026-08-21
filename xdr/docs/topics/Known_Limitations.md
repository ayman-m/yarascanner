# Known Limitations — XDR scanner & dataset consolidation

*Applies to scanner **3.4.0**. History of changes:
[release notes](../../../CHANGELOG.md).*

> The entries below describe the consolidation **engine's** internal edge cases (locking,
> quiet periods, clock skew, row ceilings, schema-version fan-out) and are unaffected by the
> v4 scanner's overwrite model — that model changed dataset *naming and lifecycle*, not this
> engine's gating logic. See [Datasets and Maintenance](Datasets_and_Maintenance.md) for what
> did change.

A residual-risk ledger for the lower-priority edge cases surfaced during this project's
systematic edge-case review, kept separate from the higher-tier items that were actually
fixed (see CHANGELOG.md) or documented in depth ([Datasets and
Maintenance](Datasets_and_Maintenance.md), [`Packs/YaraDatasetManagement/README.md`](../../Packs/YaraDatasetManagement/README.md)).

Each entry is one of three things: an **accepted risk** (real, low-probability or
low-impact, not worth the engineering cost right now), **confirmed not a gap** (checked
against the actual code, the concern doesn't apply), or **needs live verification** (can't
be resolved by reading code alone). None of these block deployment; they're recorded so a
future investigation doesn't have to rediscover the same ground.

---

## Scan lifecycle & Action Center

- **Cancel flag missed during the initial directory walk.** The cancellation watcher polls
  independently of the walker, but on a very large single directory the walker can still be
  mid-`os.walk()`/`os.scandir()` for a long stretch before yielding control — observed live,
  over an hour, before a cancel was honored. *Accepted risk*: the watcher thread itself isn't
  blocked (it's independent, same pattern as the heartbeat fix), so the cancel flag IS seen
  and `cancel_requested` IS set promptly — what's slow is the walker loop noticing and
  unwinding. A future fix would need a cancellation check inside the walk itself, not just at
  its boundaries.
- **Hostname change orphans the old shard.** The per-host shard name embeds the hostname; a
  renamed host starts a fresh shard, and the old one is only ever cleaned up by
  `--older-than-months`/`--delete-legacy`, not automatically reconciled to the "same" host.
  *Accepted risk* — no data loss, just a naming discontinuity across a rename.
- **Hostnames that slugify to the same value** (e.g. differ only in characters the shard-name
  regex strips) could theoretically collide the way case #13 covered for exact-duplicate
  hostnames. *Accepted risk* — same underlying exposure as #13, same mitigation applies if it
  ever surfaces (the per-host 6-hex suffix already reduces the odds substantially).
- **Disk full / permissions / AV interference mid-scan.** Falls through the scanner's
  existing `_mark_scan_failed()` path (sets `scan_failed`, terminal row status `failed`,
  failure reason logged) rather than any new failure mode — *confirmed not a gap*, already
  covered by the general failed-scan handling.

## Fleet-scale endpoint failures

- **Same host re-scanned before its previous scan's shard is consolidated.** *Confirmed not
  a gap* — this is exactly the "shard holds multiple scan_ids, not all ready" scenario, and
  it's directly tested (`test_orchestration_keeps_shard_holding_an_unconsolidated_second_scan`,
  `test_shard_with_second_pending_scan_keeps_shard_but_drops_ready_scans_rows`).

## Consolidation engine

- **A pass can outlive the platform's declared task timeout, silently.** Observed live: an
  `Apply` invocation's task timeout is 900s, but the platform did not appear to hard-kill the
  underlying execution at that mark — the caller's own request timed out and returned an
  error, while the run kept going server-side for roughly two hours afterward, eventually
  completing and writing its result under code that predated several since-landed fixes. A
  caller's timeout/disconnect must be treated as "unknown," never "dead" — check
  `yara_scanner_consolidation_runs` (a `started` row with no matching terminal row means a
  pass may still be running) before assuming it is safe to intervene manually, e.g. by
  clearing the consolidation lock. `DEFAULT_LOCK_STALE_SECS` (20 min) is sized to the
  *declared* timeout, not to this observed behaviour, so a genuinely long-running zombie can
  still have its lock stolen by a later run while it is mid-write — this is the leading
  explanation (not fully confirmed) for a live incident where a still-running pre-fix
  execution and a later pass both touched consolidation state around the same window.
- **`max_scans` bounds one pass; it does not make a full backlog self-draining.** A pass
  capped below the backlog size reports `stopped_early` and needs to be **re-run** (or the
  cap raised) to make further progress — the playbook does not loop back to re-check
  eligibility after `Apply` completes within a single execution.
- **Quiet period (900s default) shorter than a scan's actual worst-case drain.** Tunable via
  `--quiet-secs`/`quiet_secs`; *accepted risk* for the default value, not a design gap.
- **Endpoint clock running *ahead*, on a platform returning no usable `_insert_time`.** The
  dangerous direction (clock behind, live scan swept as abandoned) is fixed — see edge case #6
  in CHANGELOG.md — by measuring age against `max(event_timestamp_ms, _insert_time)` and
  discarding an endpoint stamp that is ahead of its own ingest stamp. With no server stamp to
  correct against, a future-dated endpoint stamp still defers that scan until real time catches
  up. *Accepted risk*: there is no trustworthy signal left in that case (clamping to `now_ms`
  resets the age to zero every pass, which livelocks the same way), and `_gate_scan` logs it
  distinctly so it is diagnosable rather than silently permanent.
- **The 7-day skew backstop (`DEFAULT_SKEW_BACKSTOP_SECS`) trades protection for liveness.**
  Past a week of endpoint silence, the endpoint stamp alone can settle both gates, so an
  endpoint whose clock is wrong by *more than a week* loses the skew protection. *Accepted
  risk*, and deliberate: it is what guarantees the abandoned cutoff cannot be deferred without
  limit (see the next entry), and a clock wrong by a week is far rarer than one wrong by hours.
- **Does `remove_lookup_data` re-stamp `_insert_time` on a shard's surviving rows?** *Needs
  live verification* — settling it requires a destructive `remove_lookup_data` against a real
  shard holding two scans. If it does (i.e. the platform implements removal as a rewrite), one
  scan's row-level cleanup re-arms an unrelated sibling scan's freshness signal on the same
  shard. The 7-day backstop above makes the answer non-load-bearing either way, which is why
  it exists.
- **`_insert_time`'s exact shape on a RAW row pull (`dataset = X`), as opposed to the
  `max(_insert_time)` aggregation.** The aggregation form is live-verified to return a usable
  number; the raw-row form (which `_stats_from_rows` uses for scans shards) is not. *Accepted
  risk* — `_as_ms` parses int/float/numeric-string/exponent/ISO-8601 and degrades to "no
  signal" otherwise, a stamp implausibly far in the future is discarded rather than adopted,
  and `_scan_stats`/`_stats_from_rows` log when a shard yields no usable server stamp, so the
  worst case is a logged reversion to pre-fix behaviour rather than a silent one.
- **Schema version bump (v2→v3) mid-flight.** *Confirmed not a gap* — `run_consolidation`
  takes an explicit `ver` and only ever touches shards of that one version;
  `check_consolidation_status`/`consolidate_all` fan out across `KNOWN_MATCHES_SCHEMA_VERSIONS`
  so both old and new shards get consolidated correctly during a rollout. A future v4 would
  need one addition to that tuple, not a redesign.
- **`_delete_many`'s partial failure across its bounded-concurrency batches.** Individual
  delete failures are caught, logged, and don't stop the batch — *accepted risk*: a failed
  delete just leaves that shard for the next run to retry (it'll still be in `shard_scans`
  next time if any scan in it isn't yet verified, or will be re-attempted if it is).
- **A scan with zero matches.** *Confirmed not a gap* — a clean scan writes no rows to the
  matches shard at all (nothing to consolidate, so it never enters the loop), and the
  scans-kind shard always has rows (the lifecycle events are unconditional), so
  `plan_consolidation`'s `source_total > 0` guard never actually blocks a real scan in
  practice.
- **Multi-tenant: could consolidation ever mix `tenant_id`s?** *Confirmed not a gap* —
  `tenant_id` is a descriptive field on each row, not a partitioning key `run_consolidation`
  groups or gates by. Isolation instead comes from `scan_id`-derived target naming: two
  different scans (even under different `tenant_id` tags) can never land in the same
  per-scan target dataset, since the target name is a pure function of `scan_id`.

## Playbook & Job orchestration

- **`GenericPolling`'s `dt` filter semantics, and the condition-task `isExists` operators.**
  Still genuinely unverified against a live run — the playbook's own YAML already
  self-documents this ("NOTE ON VERIFICATION... have not yet been exercised against a live
  run"). *Needs live verification*, not a code fix.
- **`separatecontext: true` on the polling task — do its outputs survive back to the parent
  context?** Same bucket as the item above — a live-run question, not resolvable statically.
- **Job firing every cycle during a long scan wave.** The overlap lock (edge case #31) means
  two runs can't both *write* at once, but a Job that fires every cycle and immediately backs
  off with `lock_held_by_other_run` isn't quite a livelock (it makes no false progress and
  costs no data-integrity risk) — just wasted Job-history noise. *Accepted risk*.
- **Playbook input `scan_id` as an empty string vs. genuinely unset.** `argToList(args.get("scan_id")) or None`
  already normalizes an empty string to `None` (the "all scans" case), so this is *confirmed
  not a gap* in the current scripts.

## API & data integrity

- **`_rows_for_scan`'s 50,000-row pull limit vs. the streaming path's own threshold.** For a
  single scan on a single host, 50k matches or lifecycle rows would be an extreme outlier —
  *accepted risk*, not tuned further without a concrete case motivating it.
- **Transient 502 mid-`add_data`: the retry logic only special-cases "no schema"/"not found"
  substrings**, same shape as the 401-handling gap fixed for edge case #47. *Accepted risk*
  for now — a generic transient-network retry (distinct from the schema-recreate-and-retry
  logic) would be a reasonable follow-up if 502s are ever actually observed live.
- **Client read timeout while the server keeps working — the write lands but the client never
  learns.** `delete_dataset`'s retry loop already treats a subsequent "not found"/"NoneType"
  error as "already succeeded" for exactly this reason; `add_lookup_data` has no equivalent
  reconciliation. *Accepted risk* — a duplicate-write risk bounded by the same idempotency
  checks (PATH A/A2) that already protect against every other partial-completion shape.
- **"Dataset not found" vs. a genuine permissions (403) error — distinguishable?** The client
  code branches on response text substrings, so a 403 and a 400 "not found" are NOT confused
  with each other (different status codes, different retry paths) — *confirmed not a gap*,
  though the 401 fix (edge case #47) is the more relevant auth-adjacent gap that WAS real.

## Operational & human factors

- **XQL quota exhaustion mid-run, at fleet scale.** *Accepted risk* — no special handling
  beyond the generic exception path; a hard tenant-side quota ceiling would surface as an
  unretried error today.
- **`delete_dataset` at ~60s server-side, multiplied across fleet volume.** Mitigated by
  `DELETE_CONCURRENCY=12` bounded-parallel deletes (verified live not to race across
  *different* datasets); *accepted risk* for the remaining serial cost within one batch.
- **Tenant-wide slowness making every run exceed its own time budget.** Observed directly
  during this project's own live testing. *Accepted risk* — no circuit breaker exists beyond
  each call's own timeout/retry budget; a tenant having a bad day degrades run time, not
  correctness.
- **Scanner/consolidator version skew** (an older consolidator against a newer scanner's
  schema, or vice versa). The known case (v2/v3) is fully handled (see schema-version-bump
  entry above); an *unknown future* schema version falls back to the latest known schema via
  `matches_schema_for()` rather than raising — best-effort, not a hard failure. *Accepted
  risk* for anything beyond the versions this tool actually knows about.
- **XQL compute cost per run, at fleet scale.** *Accepted risk* — not currently metered or
  budgeted beyond the tenant's own platform-level quota.
- **Pack-install `system:true` lock, making automations console-only updatable afterward.**
  Directly relevant to edge case #56's finding: a whole-pack zip install (one of the two fixes
  for the Job-picker-visibility gap) *causes* this lock as a side effect — see
  `Packs/YaraDatasetManagement/README.md`'s Deployment section for the full tradeoff. Not
  independently actionable beyond that cross-reference.
