#!/bin/bash
# CPU stress test with temperature logging that survives a hard power cut.
# Usage: ./stress-test.sh [threads] [duration_seconds]   (defaults: 20 threads, 120s)
THREADS=${1:-20}
DURATION=${2:-120}
LOG=$HOME/stress-test.log

echo "Stress test: $THREADS threads for ${DURATION}s. Logging to $LOG"
echo "elapsed_s,pkg_temp_C,max_core_C,avg_MHz,pkg_throttle_count" > "$LOG"; sync

# Prefer stress-ng if installed, otherwise fall back to openssl busy work
if command -v stress-ng >/dev/null; then
    stress-ng --cpu "$THREADS" --timeout "${DURATION}s" --quiet &
else
    openssl speed -multi "$THREADS" -seconds "$DURATION" -bytes 16384 sha256 >/dev/null 2>&1 &
fi
LOAD_PID=$!
START=$SECONDS

while kill -0 $LOAD_PID 2>/dev/null; do
    PKG=$(sensors 2>/dev/null | awk '/^Package id 0/{gsub(/[+°C]/,"",$4); print $4}')
    MAXC=$(sensors 2>/dev/null | awk '/^Core/{gsub(/[+°C]/,"",$3); if($3+0>m)m=$3+0} END{print m}')
    MHZ=$(awk '/MHz/{s+=$4;n++} END{if(n)printf "%d", s/n}' /proc/cpuinfo)
    THR=$(cat /sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count 2>/dev/null || echo 0)
    echo "$((SECONDS-START)),$PKG,$MAXC,$MHZ,$THR" >> "$LOG"
    sync   # force to disk so the last reading survives a power cut
    sleep 2
done

echo "Test completed WITHOUT crashing. Last readings:"
tail -5 "$LOG"
