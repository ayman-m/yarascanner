#!/usr/bin/env bash
# Repeats of the throttle head-to-head, with a direct before/after on the duty-cycle fix.
#
# Corrections vs the first run:
#  1) Warm-up scan first, so page-cache state is stable. The first run's baseline drifted
#     79s (cold) -> 69s -> 48s, which is why 'off' scored an impossible 0.79x "slowdown".
#  2) Load now STOPS when the scan does (SIGTERM), instead of every condition paying for
#     the full profile duration. Previously the load also ended at 300s while the script
#     scan ran 347s, leaving its last 47s unloaded - which UNDER-states the stall.
#  3) script_old runs the pre-fix scanner (park-until-CPU-drops) against the identical
#     target, load and cache state, so the fix is measured rather than asserted.
set -u

TARGET="${TARGET:-/usr/lib}"
PROFILE="${PROFILE:-600:85}"     # generous; we SIGTERM it when the scan finishes
SETTLE=15
ROUNDS="${ROUNDS:-3}"
OUT=~/throttle_repeats
rm -rf "$OUT"; mkdir -p "$OUT"
B64=$(base64 -w0 ~/test_rules.yar)

run_scan() {                     # $1=mode $2=tag $3=scanner
  local mode="$1" tag="$2" scanner="$3" start end
  start=$(date +%s)
  YARA_SCANNER_DIR=~/rp_"$tag" python3 "$scanner" "$B64" "$TARGET" low "" \
      "create_alerts=false,write_dataset=false,throttle_mode=$mode" 2>/dev/null \
      | grep SCAN_RESULT > "$OUT/scan_$tag.txt"
  end=$(date +%s)
  echo $((end - start)) > "$OUT/wall_$tag.txt"
  grep -h "THROTTLE_EVENT" ~/rp_"$tag"/logs/performance_*.log 2>/dev/null > "$OUT/events_$tag.jsonl" || true
  grep -h "THROTTLE_CONFIG" ~/rp_"$tag"/logs/performance_*.log 2>/dev/null | head -1 > "$OUT/config_$tag.txt" || true
  rm -rf ~/rp_"$tag"
  echo "[$tag] wall=$((end - start))s  $(cat "$OUT/scan_$tag.txt" | grep -o 'paused [0-9]*s' || echo 'paused ?')"
}

loaded_run() {                   # $1=mode $2=tag $3=scanner
  python3 ~/loadgen.py --profile "$PROFILE" --out "$OUT/load_$2.json" >/dev/null 2>&1 &
  local LP=$!
  sleep "$SETTLE"
  run_scan "$1" "$2" "$3"
  kill -TERM "$LP" 2>/dev/null    # stop the load now that the scan is done
  wait "$LP" 2>/dev/null
}

echo "=== warm-up scan (discarded) ==="
YARA_SCANNER_DIR=~/rp_warm python3 ~/xdr_yara_scanner.py "$B64" "$TARGET" low "" \
    "create_alerts=false,write_dataset=false,throttle_mode=off" >/dev/null 2>&1
rm -rf ~/rp_warm; echo "warm-up done"

for r in $(seq 1 "$ROUNDS"); do
  echo "########## ROUND $r ##########"

  run_scan off "scan_only_r$r" ~/xdr_yara_scanner.py     # unloaded baseline

  python3 ~/loadgen.py --profile "$PROFILE" --out "$OUT/load_load_only_r$r.json" >/dev/null 2>&1 &
  LP=$!; sleep $((SETTLE + 60)); kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null
  echo "[load_only_r$r] done"

  loaded_run script "script_old_r$r" ~/xdr_yara_scanner_old.py   # PRE-fix
  loaded_run script "script_r$r"     ~/xdr_yara_scanner.py       # POST-fix
  loaded_run os     "os_r$r"         ~/xdr_yara_scanner.py
  loaded_run off    "off_r$r"        ~/xdr_yara_scanner.py
done

echo "=== ALL ROUNDS DONE ==="
