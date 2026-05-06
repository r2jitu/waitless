#!/usr/bin/env bash
# scripts/open-browser-h3.sh — launch a Chromium browser configured to
# actually use HTTP/3 against the local unikernel.
#
# Why this exists: Chromium's default TCP-vs-QUIC race is rigged
# against QUIC on loopback. TCP's localhost handshake is ~1 ms and
# our QUIC TLS work is ~5 ms; TCP wins every race, QUIC gets
# cancelled mid-handshake, and the alt-svc cache marks `quic
# localhost:<port>` broken. Subsequent visits then skip QUIC outright
# even though our server is correct (`test_h3_health` passes;
# `--origin-to-force-quic-on` produces a clean handshake).
#
# This isn't a problem in production — at any non-trivial RTT QUIC
# wins races easily. It's purely a localhost development annoyance.
# `--origin-to-force-quic-on=localhost:<port>` bypasses the race.
# `--user-data-dir=/tmp/...` keeps it from poisoning the user's
# real browser profile.
#
# Usage:
#   ./scripts/open-browser-h3.sh                      # defaults: Arc, port 8443
#   ./scripts/open-browser-h3.sh --browser=chrome     # Google Chrome
#   ./scripts/open-browser-h3.sh --port=18443         # custom port

set -euo pipefail

BROWSER="arc"
PORT="8443"
URL=""

for arg in "$@"; do
    case "$arg" in
        --browser=*) BROWSER="${arg#--browser=}" ;;
        --port=*)    PORT="${arg#--port=}" ;;
        --url=*)     URL="${arg#--url=}" ;;
        *) echo "unknown arg: $arg" >&2; exit 1 ;;
    esac
done
URL="${URL:-https://localhost:${PORT}/}"

case "$BROWSER" in
    arc)    APP="/Applications/Arc.app/Contents/MacOS/Arc" ;;
    chrome) APP="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ;;
    edge)   APP="/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ;;
    *) echo "unknown browser: $BROWSER (try arc / chrome / edge)" >&2; exit 1 ;;
esac

if [[ ! -x "$APP" ]]; then
    echo "browser not installed: $APP" >&2
    exit 1
fi

DATA_DIR="/tmp/${BROWSER}-h3-test"
mkdir -p "$DATA_DIR"

echo "Launching $BROWSER with forced QUIC for localhost:$PORT" >&2
echo "  URL:        $URL" >&2
echo "  Profile:    $DATA_DIR (sandboxed; doesn't touch your real profile)" >&2
echo "  Verify h3:  DevTools > Network > right-click columns > Protocol" >&2
echo >&2

exec "$APP" \
    --user-data-dir="$DATA_DIR" \
    --origin-to-force-quic-on="localhost:$PORT" \
    "$URL"
