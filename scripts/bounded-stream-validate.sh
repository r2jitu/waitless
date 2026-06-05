#!/usr/bin/env bash
# scripts/bounded-stream-validate.sh — bounded-memory + large-transfer
# correctness proof for the h1 streaming-response paths, run FROM kvm-vm
# against the deployed `waitless-webserver` over the internal GCE network
# (gVNIC, production-shape). HVF's userspace TCP proxy lies about large
# transfers, so this must run on GCE; see docs/streaming-response.md.
#
# Both checks sample `/obs` `heap_allocated_bytes` mid-transfer: a bounded
# path grows live heap by O(chunk) (KB–MB), a buffering path by O(payload).
#
#   - /stream (1 GiB generated, h1, `CellSink`): exact byte count,
#     all-zero, live heap ~flat mid-transfer, heap_oom==0.
#   - /echo   (256 MiB upload, h1, app-written read_chunk->write duplex):
#     sha256(response)==sha256(upload), live heap ~flat, heap_oom==0.
#   - server still serving /health 200 after each.
#
# Requires `waitless-webserver` + `kvm-vm` RUNNING in the deploy zone
# (e.g. via `scripts/gcp-deploy-bench.sh --keep-running`). Reads the
# server IP from `gcloud describe` — never hardcode it.
set -euo pipefail
UNI="${WAITLESS_GCE_NAME:-waitless-webserver}"
KVM="${GCP_KVM_VM_NAME:-kvm-vm}"
ZONE="${WAITLESS_GCE_ZONE:-us-west1-c}"
UNI_IP="$(gcloud compute instances describe "$UNI" --zone="$ZONE" \
    --format='value(networkInterfaces[0].networkIP)')"
echo "==> UNI_IP read from describe: $UNI_IP" >&2

gcloud compute ssh "$KVM" --zone="$ZONE" --command="bash -s" <<REMOTE
set -uo pipefail
IP="$UNI_IP"

hb() { curl -s "http://\$IP/obs" | grep -oE '"heap_allocated_bytes":[0-9]+' | head -1 | grep -oE '[0-9]+'; }
ho() { curl -s "http://\$IP/obs" | grep -oE '"heap_oom":[0-9]+' | head -1 | grep -oE '[0-9]+'; }

OBS_SIZE=\$(curl -s "http://\$IP/obs" | wc -c)
echo "obs_size=\$OBS_SIZE (must be >500)"
if [ "\$OBS_SIZE" -lt 500 ]; then echo "FAIL: /obs too small — server not healthy"; exit 1; fi

mib() { echo "\$(( \$1 / 1024 / 1024 ))MiB"; }
sample_during() { # \$1=child pid ; echo max heap seen
  local pid="\$1" maxh base cur
  base=\$(hb || echo 0); maxh=\$base
  for _ in \$(seq 1 200); do
    cur=\$(hb 2>/dev/null || echo 0)
    if [ -n "\$cur" ] && [ "\$cur" -gt "\$maxh" ] 2>/dev/null; then maxh=\$cur; fi
    kill -0 "\$pid" 2>/dev/null || break
    sleep 0.1
  done
  echo "\$maxh"
}

echo "================ /stream (1 GiB, h1) ================"
BASE=\$(hb); echo "heap_base=\$BASE (\$(mib \$BASE))"
curl -s "http://\$IP/stream" -o /tmp/stream.out -w 'stream_http=%{http_code} stream_bytes=%{size_download}\n' &
SPID=\$!
MAXH=\$(sample_during "\$SPID")
wait "\$SPID" 2>/dev/null || true
SBYTES=\$(stat -c %s /tmp/stream.out 2>/dev/null || wc -c </tmp/stream.out)
NONZERO=\$(tr -d '\\0' </tmp/stream.out | wc -c)
echo "stream_bytes=\$SBYTES (want 1073741824) nonzero_bytes=\$NONZERO (want 0)"
echo "heap_max_during=\$MAXH (\$(mib \$MAXH))  heap_base=\$BASE  growth=\$(( MAXH - BASE )) bytes"
echo "heap_oom=\$(ho)"
rm -f /tmp/stream.out

echo "================ /echo (256 MiB upload, h1) ================"
head -c 268435456 /dev/urandom > /tmp/up.bin
UPSHA=\$(sha256sum /tmp/up.bin | cut -d' ' -f1)
echo "upload_sha=\$UPSHA"
BASE2=\$(hb); echo "heap_base=\$BASE2 (\$(mib \$BASE2))"
curl -s "http://\$IP/echo" -H 'Content-Type: application/octet-stream' \
     --data-binary @/tmp/up.bin -o /tmp/echo.out \
     -w 'echo_http=%{http_code} echo_bytes=%{size_download}\n' &
EPID=\$!
MAXH2=\$(sample_during "\$EPID")
wait "\$EPID" 2>/dev/null || true
EBYTES=\$(stat -c %s /tmp/echo.out 2>/dev/null || wc -c </tmp/echo.out)
ECHOSHA=\$(sha256sum /tmp/echo.out | cut -d' ' -f1)
echo "echo_bytes=\$EBYTES (want 268435456)"
echo "echo_sha=\$ECHOSHA"
if [ "\$ECHOSHA" = "\$UPSHA" ]; then echo "ECHO INTEGRITY: OK (sha match)"; else echo "ECHO INTEGRITY: FAIL (sha mismatch)"; fi
echo "heap_max_during=\$MAXH2 (\$(mib \$MAXH2))  heap_base=\$BASE2  growth=\$(( MAXH2 - BASE2 )) bytes"
echo "heap_oom=\$(ho)"
rm -f /tmp/up.bin /tmp/echo.out

echo "================ liveness ================"
echo "health_after=\$(curl -s -o /dev/null -w '%{http_code}' http://\$IP/health)"
REMOTE
