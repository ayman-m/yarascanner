#!/usr/bin/env bash
# Run C: does CPU throttling earn its keep on SMALL hosts?
#
# On this 8-core box, throttling bought ~3% host protection (degradation 1.04 vs 1.01
# for 'off') because the scanner is hard-capped at 2 worker threads and simply cannot
# contend. The hypothesis is that the same 2 workers ARE the whole machine on a 2-core
# endpoint, where throttling should genuinely matter.
#
# METHOD - emulation, not a real small host. Both the scanner and the load generator are
# confined with taskset to N cores, and the generator offers N-1 threads. Because
# psutil.cpu_percent() still reports across ALL 8 host cores, the scanner's thresholds are
# SCALED by N/8 so the throttle sees equivalent relative pressure: saturating 2 of 8 cores
# reads as 25% system-wide, which must compare against 80%*(2/8)=20% to mean "busy".
#
# Caveat this cannot remove: the other 8-N cores are idle and the kernel knows it, so the
# scheduler has slack a genuine small host would not. Treat as indicative, not definitive.
set -u

TARGET="${TARGET:-/usr}"
OUT=~/throttle_cores3
rm -rf "$OUT"; mkdir -p "$OUT"
B64=$(base64 -w0 ~/test_rules.yar)
HOST_CORES=$(nproc)

run_one() {   # $1=ncores $2=mode $3=tag $4=high $5=crit $6=cpuset
  local n="$1" mode="$2" tag="$3" high="$4" crit="$5" cpuset="$6" start end
  start=$(date +%s)
  taskset -c "$cpuset" env YARA_SCANNER_DIR=~/cr_"$tag" \
      python3 ~/xdr_yara_scanner.py "$B64" "$TARGET" low "" \
      "create_alerts=false,write_dataset=false,throttle_mode=$mode,cpu_high_threshold=$high,cpu_critical_threshold=$crit" \
      2>/dev/null | grep SCAN_RESULT > "$OUT/scan_$tag.txt"
  end=$(date +%s)
  echo $((end - start)) > "$OUT/wall_$tag.txt"
  grep -h "THROTTLE_EVENT" ~/cr_"$tag"/logs/performance_*.log 2>/dev/null > "$OUT/events_$tag.jsonl" || true
  rm -rf ~/cr_"$tag"
  echo "[$tag] wall=$((end - start))s $(grep -o 'paused [0-9]*s' "$OUT/scan_$tag.txt" || echo '')"
}

for N in 2 4 8; do
  CPUSET="0-$((N-1))"
  SCALE_H=$(python3 -c "print(round(80.0*$N/$HOST_CORES,1))")
  SCALE_C=$(python3 -c "print(round(90.0*$N/$HOST_CORES,1))")
  LTHREADS=$N
  echo "########## emulating ${N}-core host (cpuset=$CPUSET high=$SCALE_H crit=$SCALE_C loadthreads=$LTHREADS) ##########"

  # unloaded baseline on the same cpuset
  run_one "$N" off "base_c$N" 100 100 "$CPUSET"

  # load-only baseline: what the competing workload achieves with no scan
  taskset -c "$CPUSET" python3 ~/loadgen.py --profile "300:100" --threads "$LTHREADS" \
      --out "$OUT/load_only_c$N.json" >/dev/null 2>&1 &
  LP=$!; sleep 135; kill -TERM $LP 2>/dev/null; wait $LP 2>/dev/null
  echo "[load_only_c$N] done"

  for mode in script os off; do
    taskset -c "$CPUSET" python3 ~/loadgen.py --profile "600:100" --threads "$LTHREADS" \
        --out "$OUT/load_${mode}_c$N.json" >/dev/null 2>&1 &
    LP=$!
    sleep 15
    run_one "$N" "$mode" "${mode}_c$N" "$SCALE_H" "$SCALE_C" "$CPUSET"
    kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
  done
done

echo "=== CORES DONE ==="
