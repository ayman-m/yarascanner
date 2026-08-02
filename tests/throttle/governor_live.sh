#!/usr/bin/env bash
# Validate the CPU-governor promise on a live endpoint.
#
#   1) ANTI-STALL REGRESSION: under saturating external load the scan must COMPLETE in
#      reasonable time. This is the exact scenario in which the OLD design took 593s
#      instead of 9s, parking 98.5% of the scan.
#   2) THE PROMISE: the scanner's own share must stay at or under target. A sustained
#      own ~= cpu_count x target means the normalisation in normalise_own is not being
#      applied - the highest-risk detail in the design, and invisible without this check.
#   3) Governing must not cripple an idle host.
#   4) Core-scaled workers must beat the old 2-worker ceiling.
set -u
TARGET="${TARGET:-/usr}"
OUT=~/governor_live; rm -rf "$OUT"; mkdir -p "$OUT"
B64=$(base64 -w0 ~/test_rules.yar)

run() {   # $1=tag  $2=options
  local tag="$1" opts="$2" s e
  s=$(date +%s)
  YARA_SCANNER_DIR=~/gv_"$tag" python3 ~/xdr_yara_scanner.py "$B64" "$TARGET" low "" "$opts" \
      2>/dev/null | grep SCAN_RESULT > "$OUT/scan_$tag.txt"
  e=$(date +%s); echo $((e-s)) > "$OUT/wall_$tag.txt"
  grep -h "CPU_GOVERNOR" ~/gv_"$tag"/logs/performance_*.log 2>/dev/null > "$OUT/gov_$tag.jsonl" || true
  cp ~/gv_"$tag"/logs/scan_summary_*.json "$OUT/summary_$tag.json" 2>/dev/null || true
  rm -rf ~/gv_"$tag"
  echo "[$tag] wall=$((e-s))s $(cat "$OUT/scan_$tag.txt" 2>/dev/null | sed 's/SCAN_RESULT: //')"
}

echo "=== 1. idle, governed (headroom) ==="
run idle_headroom "create_alerts=false,write_dataset=false,cpu_guarantee=headroom"

echo "=== 2. idle, ungoverned (throughput ceiling) ==="
run idle_none "create_alerts=false,write_dataset=false,cpu_guarantee=none"

echo "=== 3. ANTI-STALL: saturating load, headroom ==="
python3 ~/loadgen.py --profile "900:100" --threads "$(nproc)" --out "$OUT/load_headroom.json" >/dev/null 2>&1 &
LP=$!; sleep 15
run loaded_headroom "create_alerts=false,write_dataset=false,cpu_guarantee=headroom"
kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null

echo "=== 4. THE PROMISE: saturating load, budget=20% ==="
python3 ~/loadgen.py --profile "900:100" --threads "$(nproc)" --out "$OUT/load_budget.json" >/dev/null 2>&1 &
LP=$!; sleep 15
run loaded_budget "create_alerts=false,write_dataset=false,cpu_guarantee=budget,cpu_budget_pct=20"
kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null

echo "=== GOVERNOR LIVE DONE ==="
