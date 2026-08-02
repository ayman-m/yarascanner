#!/usr/bin/env bash
# Run B: threshold-ZONE behaviour. Walks the load through every zone in ONE scan:
#   idle -> below high -> above high -> above CRITICAL -> back below high -> idle
#
# Why: the flat-load run only ever exercised "just above high". Two zones that matter
# most were untested - the critical branch (which selects the 4.0 sleep ratio, a code
# path that had never executed) and RECOVERY, which is precisely where the original bug
# lived: the old code required CPU below (high - resume_margin) to resume, and never got
# it while external load persisted. A test that never lowers CPU cannot prove recovery.
#
# THROTTLE_EVENT lines carry wall-clock timestamps and the generator samples CPU every
# second, so events can be aligned to zones after the fact.
set -u

TARGET="${TARGET:-/}"            # large enough that even unthrottled modes span zones
OUT=~/throttle_zones
rm -rf "$OUT"; mkdir -p "$OUT"
B64=$(base64 -w0 ~/test_rules.yar)

run_scan() {                     # $1=mode $2=tag $3=scanner
  local mode="$1" tag="$2" scanner="$3" start end
  start=$(date +%s)
  echo "$start" > "$OUT/start_$tag.txt"
  YARA_SCANNER_DIR=~/zn_"$tag" python3 "$scanner" "$B64" "$TARGET" low "" \
      "create_alerts=false,write_dataset=false,throttle_mode=$mode" 2>/dev/null \
      | grep SCAN_RESULT > "$OUT/scan_$tag.txt"
  end=$(date +%s)
  echo $((end - start)) > "$OUT/wall_$tag.txt"
  grep -h "THROTTLE_EVENT" ~/zn_"$tag"/logs/performance_*.log 2>/dev/null > "$OUT/events_$tag.jsonl" || true
  grep -h "THROTTLE_CONFIG" ~/zn_"$tag"/logs/performance_*.log 2>/dev/null | head -1 > "$OUT/config_$tag.txt" || true
  rm -rf ~/zn_"$tag"
  echo "[$tag] wall=$((end - start))s events=$(wc -l < "$OUT/events_$tag.jsonl" 2>/dev/null || echo 0)"
}

echo "=== sizing: unthrottled baseline on $TARGET ==="
run_scan off zbaseline ~/xdr_yara_scanner.py
BASE=$(cat "$OUT/wall_zbaseline.txt")
[ "$BASE" -lt 30 ] && BASE=30
ZONE=$(( BASE / 3 )); [ "$ZONE" -lt 40 ] && ZONE=40
echo "baseline=${BASE}s -> zone=${ZONE}s per stage"

# duty -> approx system CPU on this host (calibrated earlier: duty 85 => ~74%)
#   50  => ~44%  below high(80)
#   85  => ~74%  + scan crosses high
#   100 => ~87%  + scan crosses critical(90)
PROFILE="20:0,${ZONE}:50,${ZONE}:85,${ZONE}:100,${ZONE}:50,20:0"
echo "profile=$PROFILE"
echo "$PROFILE" > "$OUT/profile.txt"
echo "$ZONE"    > "$OUT/zone_secs.txt"

for spec in "script:script_old:$HOME/xdr_yara_scanner_old.py" \
            "script:script_new:$HOME/xdr_yara_scanner.py" \
            "os:os:$HOME/xdr_yara_scanner.py" \
            "off:off:$HOME/xdr_yara_scanner.py"; do
  mode="${spec%%:*}"; rest="${spec#*:}"; tag="${rest%%:*}"; scanner="${rest#*:}"
  echo "=== zone walk: $tag ==="
  python3 ~/loadgen.py --profile "$PROFILE" --out "$OUT/load_$tag.json" >/dev/null 2>&1 &
  LP=$!
  sleep 20                       # let the idle stage pass before the scan starts
  run_scan "$mode" "$tag" "$scanner"
  kill -TERM "$LP" 2>/dev/null
  wait "$LP" 2>/dev/null
done

echo "=== ZONES DONE ==="
