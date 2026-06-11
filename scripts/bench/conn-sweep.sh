#!/usr/bin/env bash
# conn-sweep.sh — RPS + latency at each concurrency level, driven from
# TWO GCE loadgens (each takes half the connections). Produces the
# per-connection-count curve (rps @ N conns, p50/p99 @ N conns) that
# docs/assets/benchmark-curve.* is rendered from.
#
# Per point: both loadgens run `wrk -t8 -c N/2` in parallel; rps is
# summed; latency is reported per-loadgen. Mid-run, the server's
# actual ESTABLISHED-connection count is sampled — from `/obs`
# (waitless) or `ss -s` over ssh (a Linux peer) — so "N concurrent
# connections" is a measured server-side fact, not a wrk parameter.
#
# Usage: conn-sweep.sh SERVER_IP LABEL [PROTO=https] [DUR=30] [CONNS="1000 4000 ..."]
# Env:   LG1, LG2 (loadgen instance names), ZONE,
#        SAMPLE=obs|ss|none (default obs), SERVER_SSH (instance name, for SAMPLE=ss),
#        OUT (jsonl path, default /tmp/sweep-<LABEL>.jsonl),
#        WRK_TIMEOUT (default 10s — use 30s + DUR>=75 at >=40 K conns
#        so the TLS-handshake establishment storm doesn't read as
#        client-side connect failures)
set -u
SERVER_IP="${1:?server ip}"; LABEL="${2:?label}"
PROTO="${3:-https}"; DUR="${4:-30}"
CONNS_LIST="${5:-1000 2000 4000 8000 16000 24000 32000 40000 50000 65000 80000}"
LG1="${LG1:-kvm-vm}"; LG2="${LG2:-waitless-peer-nginx}"; ZONE="${ZONE:-us-west1-c}"
SAMPLE="${SAMPLE:-obs}"; SERVER_SSH="${SERVER_SSH:-}"
OUT="${OUT:-/tmp/sweep-${LABEL}.jsonl}"
WRK_TIMEOUT="${WRK_TIMEOUT:-10s}"
URL="${PROTO}://${SERVER_IP}/health"

gssh() { # $1=instance $2=command $3=timeout
  timeout "${3:-$((DUR + 90))}" gcloud compute ssh "$1" --zone="$ZONE" --command="$2"
}

# One-time loadgen prep: fd limit is per-session (set inline below);
# port range + tw_reuse are host sysctls.
prep_lg() {
  gssh "$1" "sudo sysctl -wq net.ipv4.ip_local_port_range='1024 65535' net.ipv4.tcp_tw_reuse=1; ulimit -Hn" 120
}

run_wrk() { # $1=loadgen $2=conns $3=outfile
  gssh "$1" "ulimit -Sn 1048576; wrk -t8 -c$2 -d${DUR}s --latency --timeout $WRK_TIMEOUT $URL 2>&1" >"$3" 2>/dev/null
}

# Mid-run server-side established-connection sample.
sample_conns() { # stdout: integer or empty
  case "$SAMPLE" in
  obs) # waitless: tcp.live_conns gauge via /obs (counts non-Closed slots)
    gssh "$LG1" "sleep $((DUR / 2)); curl -sk --max-time 10 https://${SERVER_IP}/obs | grep -o '\"live_conns\":[0-9]*' | head -1 | cut -d: -f2" $((DUR / 2 + 30)) ;;
  ss) # Linux peer: kernel's ESTABLISHED count
    gssh "${SERVER_SSH:?SAMPLE=ss needs SERVER_SSH}" "sleep $((DUR / 2)); ss -s | sed -n 's/.*estab \([0-9]*\).*/\1/p'" $((DUR / 2 + 30)) ;;
  *) echo "" ;;
  esac
}

rps()    { grep 'Requests/sec' "$1" | awk '{print $2}'; }
reqs()   { awk '/requests in/{print $1}' "$1"; }
pctl()   { awk -v p="$2%" '/Latency Distribution/{f=1} f&&$1==p{print $2; exit}' "$1"; }
errs()   { grep 'Socket errors' "$1" | sed 's/^ *//' || echo "Socket errors: none"; }
non2xx() { grep 'Non-2xx' "$1" | awk '{print $NF}'; }

echo "## sweep: $LABEL  ($PROTO, ${DUR}s/point, 2x wrk -t8, sample=$SAMPLE)"
echo "   prep: $(prep_lg "$LG1" | tail -1) / $(prep_lg "$LG2" | tail -1) max fds"
: >"$OUT"

for N in $CONNS_LIST; do
  HALF=$((N / 2))
  O1="/tmp/sweep-${LABEL}-${N}-lg1.txt"; O2="/tmp/sweep-${LABEL}-${N}-lg2.txt"
  run_wrk "$LG1" "$HALF" "$O1" &
  P1=$!
  run_wrk "$LG2" "$HALF" "$O2" &
  P2=$!
  LIVE=$(sample_conns | tr -dc '0-9')
  wait $P1 $P2
  R1=$(rps "$O1"); R2=$(rps "$O2")
  SUM=$(awk "BEGIN{printf \"%.0f\", ${R1:-0}+${R2:-0}}")
  REQS=$(awk "BEGIN{printf \"%.0f\", $(reqs "$O1" || echo 0)+$(reqs "$O2" || echo 0)}")
  printf '%7d conns: %8s rps  live=%-6s p50=%s/%s p99=%s/%s  reqs=%s\n' \
    "$N" "$SUM" "${LIVE:-?}" \
    "$(pctl "$O1" 50)" "$(pctl "$O2" 50)" "$(pctl "$O1" 99)" "$(pctl "$O2" 99)" "$REQS"
  E1=$(errs "$O1"); E2=$(errs "$O2")
  [ -n "$E1$E2" ] && printf '             lg1: %s | lg2: %s\n' "${E1:-—}" "${E2:-—}"
  printf '{"label":"%s","proto":"%s","conns":%d,"rps":%s,"live_conns":"%s","rps1":"%s","rps2":"%s","p50_1":"%s","p50_2":"%s","p99_1":"%s","p99_2":"%s","errs1":"%s","errs2":"%s","non2xx":"%s","requests":"%s","dur":%d}\n' \
    "$LABEL" "$PROTO" "$N" "${SUM:-0}" "$LIVE" "$R1" "$R2" \
    "$(pctl "$O1" 50)" "$(pctl "$O2" 50)" "$(pctl "$O1" 99)" "$(pctl "$O2" 99)" \
    "$E1" "$E2" "$(non2xx "$O1")+$(non2xx "$O2")" "$REQS" "$DUR" >>"$OUT"
done
echo "JSONL: $OUT"
