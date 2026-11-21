#!/bin/zsh
# A/B benchmark: Transmission (transmission-cli) vs Astor on the same torrent,
# same duration, run one after the other on the same network.
#   scripts/bench.sh <file.torrent> [seconds] [workdir]
set -u
TORRENT=${1:?usage: bench.sh file.torrent [seconds] [workdir]}
SECS=${2:-120}
WORK=${3:-${TMPDIR:-/tmp}/astor-bench-$$}
ASTOR=${ASTOR:-$(cd "$(dirname "$0")/.." && pwd)/.build/release/astor}
mkdir -p "$WORK/tr" "$WORK/trconf" "$WORK/as" "$WORK/asstate"
# Sparse files for both clients so `du` measures bytes actually downloaded.
print '{ "preallocation": 0 }' > "$WORK/trconf/settings.json"

dir_bytes() { du -sk "$1" 2>/dev/null | awk '{print $1 * 1024}'; }

run_transmission() {
  echo "== Transmission ($SECS s)"
  transmission-cli -g "$WORK/trconf" -w "$WORK/tr" -ep "$TORRENT" > "$WORK/tr.log" 2>&1 &
  TP=$!
  sleep "$SECS"
  kill -INT $TP 2>/dev/null; sleep 3; kill -9 $TP 2>/dev/null
  # Transmission allocates more disk than it writes, so `du` overstates it: use the
  # "downloaded" counter from its resume file instead.
  TB=$(python3 -I -c 'import re,sys,glob
fs=glob.glob(sys.argv[1]+"/resume/*.resume")
m=re.search(rb"downloaded" + rb"i(\d+)e", open(fs[0],"rb").read()) if fs else None
print(m.group(1).decode() if m else 0)' "$WORK/trconf")
}
run_astor() {
  echo "== Astor ($SECS s)"
  "$ASTOR" download "$TORRENT" -o "$WORK/as" --state "$WORK/asstate" --exit-after "$SECS" > "$WORK/as.log" 2>&1
  AB=$(dir_bytes "$WORK/as")
}
# ORDER=astor-first to check for order effects (the first client warms the swarm).
if [[ "${ORDER:-}" == astor-first ]]; then run_astor; run_transmission; else run_transmission; run_astor; fi

printf "\nTransmission: %6.1f MiB  avg %5.2f MiB/s\n" $(( TB / 1048576.0 )) $(( TB / 1048576.0 / SECS ))
printf "Astor:        %6.1f MiB  avg %5.2f MiB/s\n" $(( AB / 1048576.0 )) $(( AB / 1048576.0 / SECS ))
echo "(logs and data in $WORK — delete it when done)"
