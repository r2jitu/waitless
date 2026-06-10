#!/usr/bin/env bash
# Classify the under-loss collapse: single-request transfers (no keep-alive
# idle gaps) + server-side TCP recovery counters, so we can tell a real
# RTO-dominated loss-recovery problem from a measurement artifact.
set -u
SRV="${1:?server ip}"; DEV="${DEV:-ens3}"
netem_down(){ sudo tc qdisc del dev "$DEV" ingress 2>/dev/null; sudo tc qdisc del dev ifb0 root 2>/dev/null; }
trap netem_down EXIT
netem_up(){
  sudo modprobe ifb act_mirred cls_u32 sch_ingress sch_netem 2>/dev/null
  sudo ip link add ifb0 type ifb 2>/dev/null || true; sudo ip link set ifb0 up; netem_down
  sudo tc qdisc add dev "$DEV" handle ffff: ingress
  sudo tc filter add dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
  sudo tc qdisc add dev ifb0 root netem delay "$1" loss "$2"
}
# pull a few tcp diag counters from /obs (best-effort grep)
tcpdiag(){ curl -sk --max-time 5 "https://$SRV/obs" | tr ',' '\n' | grep -iE "retrans|rtx|fast_retx|rto|dup_ack|sack|fast_retransmit|timeout" | head -20; }

echo "== single-request transfers, no keep-alive multiplexing =="
netem_down
echo "## CLEAN single /static-1m x3"
for i in 1 2 3; do curl -sk --http1.1 -o /dev/null -w "  clean: %{speed_download} B/s  time=%{time_total}s\n" "https://$SRV/static-1m"; done

netem_up 25ms 1%
echo "## 25ms 1%: single /static-256k x3 (fewer losses)"
for i in 1 2 3; do curl -sk --http1.1 -o /dev/null -w "  256k: %{speed_download} B/s  time=%{time_total}s\n" "https://$SRV/static-256k"; done
echo "## 25ms 1%: single /static-1m x3"
echo "  -- server tcp diag BEFORE --"; tcpdiag
for i in 1 2 3; do curl -sk --http1.1 -o /dev/null -w "  1m: %{speed_download} B/s  time=%{time_total}s\n" "https://$SRV/static-1m"; done
echo "  -- server tcp diag AFTER --"; tcpdiag
netem_down
echo "== done =="
