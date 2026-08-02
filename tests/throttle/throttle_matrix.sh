#!/usr/bin/env bash
# Head-to-head: script vs os vs off CPU throttling, under identical open-loop load.
# Runs entirely on the endpoint. No tenant involved.
set -u

TARGET="${TARGET:-/usr}"
PROFILE="${PROFILE:-300:85}"     # constant heavy load, long enough to outlast the slowest scan
SETTLE=15                        # let load reach steady state before the scan starts
OUT=~/throttle_results
mkdir -p "$OUT"
B64=$(base64 -w0 ~/test_rules.yar)

run_scan() {                     # $1=mode $2=tag
  local mode="$1" tag="$2" start end
  start=$(date +%s)
  YARA_SCANNER_DIR=~/sh_"$tag" python3 ~/xdr_yara_scanner.py "$B64" "$TARGET" low "" \
      "create_alerts=false,write_dataset=false,throttle_mode=$mode" 2>/dev/null \
      | grep SCAN_RESULT > "$OUT/scan_$tag.txt"
  end=$(date +%s)
  echo $((end - start)) > "$OUT/wall_$tag.txt"
  # THROTTLE_EVENT counts straight from the scanner's own performance log
  grep -h "THROTTLE_EVENT" ~/sh_"$tag"/logs/performance_*.log 2>/dev/null \
      > "$OUT/events_$tag.jsonl" || true
  grep -h "THROTTLE_CONFIG" ~/sh_"$tag"/logs/performance_*.log 2>/dev/null \
      | head -1 > "$OUT/config_$tag.txt" || true
  echo "[$tag] wall=$((end - start))s pause_starts=$(grep -c pause_start "$OUT/events_$tag.jsonl" 2>/dev/null || echo 0)"
}

echo "=== 1/5 scan_only (baseline wall-clock, no load) ==="
run_scan script scan_only

echo "=== 2/5 load_only (baseline work rate, no scan) ==="
python3 ~/loadgen.py --profile "$PROFILE" --out "$OUT/load_load_only.json" >/dev/null 2>&1
echo "[load_only] done"

for mode in script os off; do
  echo "=== $mode: scan + load ==="
  python3 ~/loadgen.py --profile "$PROFILE" --out "$OUT/load_$mode.json" >/dev/null 2>&1 &
  LOADPID=$!
  sleep "$SETTLE"
  run_scan "$mode" "$mode"
  wait $LOADPID 2>/dev/null
done

echo "=== DONE ==="
ls -la "$OUT"
