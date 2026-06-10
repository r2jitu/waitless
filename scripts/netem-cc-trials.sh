#!/usr/bin/env bash
# Collect N single-object transfer times under a netem profile so the MEDIAN
# rejects the bimodal tail-loss RTO outliers and exposes the steady-state
# (congestion-curve-bound) throughput. Run ON the loadgen VM.
#   bash netem-cc-trials.sh <server-ip> <arm-label>
set -u
SRV="${1:?ip}"; ARM="${2:-arm}"; DEV="${DEV:-ens3}"; N="${N:-15}"
netem_down(){ sudo tc qdisc del dev "$DEV" ingress 2>/dev/null; sudo tc qdisc del dev ifb0 root 2>/dev/null; }
trap netem_down EXIT
netem_up(){
  sudo modprobe ifb act_mirred cls_u32 sch_ingress sch_netem 2>/dev/null
  sudo ip link add ifb0 type ifb 2>/dev/null || true; sudo ip link set ifb0 up; netem_down
  sudo tc qdisc add dev "$DEV" handle ffff: ingress
  sudo tc filter add dev "$DEV" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0
  sudo tc qdisc add dev ifb0 root netem delay "$1" loss "$2"
}
trials(){ # delay loss obj
  netem_up "$1" "$2"
  local times=() i t
  for i in $(seq "$N"); do
    t=$(curl -sk --http1.1 -o /dev/null -w '%{speed_download}' "https://$SRV/$3")
    times+=("$t"); printf "  [%s] %s %s %s #%d: %.3f MB/s\n" "$ARM" "$1" "$2" "$3" "$i" "$(awk -v x=$t 'BEGIN{print x/1e6}')"
  done
  netem_down
  printf '%s\n' "${times[@]}" | sort -n | awk -v arm="$ARM" -v d="$1" -v l="$2" -v o="$3" '
    {v[NR]=$1/1e6} END{
      med=(NR%2)?v[(NR+1)/2]:(v[NR/2]+v[NR/2+1])/2;
      stalls=0; for(i=1;i<=NR;i++) if(v[i]<0.2) stalls++;
      printf "  >> [%s] %s %s %s  MEDIAN=%.3f MB/s  min=%.3f max=%.3f  stalls(<0.2)=%d/%d\n", arm,d,l,o,med,v[1],v[NR],stalls,NR
    }'
}
echo "== arm=$ARM N=$N =="
trials 25ms 1% static-1m
trials 50ms 1% static-1m
echo "== done $ARM =="
