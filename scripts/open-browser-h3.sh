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
# `--ignore-certificate-errors-spki-list=<base64-sha256-of-spki>`
# accepts the committed self-signed dev cert without needing a
# mkcert root in the system keychain. Over QUIC, Chrome's TLS check
# is strict — a self-signed leaf triggers `certificate_unknown(46)`
# and `ERR_QUIC_HANDSHAKE_FAILED`. The plain `--ignore-certificate-
# errors` flag is documented to disable cert validation but in
# practice does NOT cover QUIC's separate verification path in
# recent Chrome (148+), so we use the SPKI-list flag which Chromium
# specifically routes through both the HTTPS and QUIC TLS stacks.
#
# We compute the hash from `apps/webserver/dev_certs/dev_cert.pem`
# at launch time so it tracks any cert regen (regen.sh, regen-
# mkcert.sh) without manual updates. Safe to enable: the
# sandboxed `--user-data-dir` profile is isolated; the SPKI hash
# pins exactly one cert (this one), nothing else.
#
# Usage:
#   ./scripts/open-browser-h3.sh                      # defaults: Chrome, port 8443
#   ./scripts/open-browser-h3.sh --browser=arc        # Arc
#   ./scripts/open-browser-h3.sh --port=18443         # custom port

set -euo pipefail

BROWSER="chrome"
PORT="8443"
URL=""

for arg in "$@"; do
    case "$arg" in
    --browser=*) BROWSER="${arg#--browser=}" ;;
    --port=*) PORT="${arg#--port=}" ;;
    --url=*) URL="${arg#--url=}" ;;
    *)
        echo "unknown arg: $arg" >&2
        exit 1
        ;;
    esac
done
URL="${URL:-https://localhost:${PORT}/}"

case "$BROWSER" in
arc) APP="/Applications/Arc.app/Contents/MacOS/Arc" ;;
chrome) APP="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ;;
edge) APP="/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ;;
*)
    echo "unknown browser: $BROWSER (try arc / chrome / edge)" >&2
    exit 1
    ;;
esac

if [[ ! -x "$APP" ]]; then
    echo "browser not installed: $APP" >&2
    exit 1
fi

DATA_DIR="/tmp/${BROWSER}-h3-test"
mkdir -p "$DATA_DIR"

# Compute the SPKI hash of the committed dev cert so Chrome accepts
# it as a pinned exception. Pulling from the same source tree the
# unikernel embeds keeps `regen.sh` / `regen-mkcert.sh` working
# without further script edits.
DEV_CERT="$(cd "$(dirname "$0")/.." && pwd)/apps/webserver/dev_certs/dev_cert.pem"
if [[ ! -f "$DEV_CERT" ]]; then
    echo "dev_cert.pem not found at $DEV_CERT" >&2
    exit 1
fi
SPKI_HASH=$(
    openssl x509 -in "$DEV_CERT" -pubkey -noout |
        openssl pkey -pubin -outform der |
        openssl dgst -sha256 -binary |
        base64
)

echo "Launching $BROWSER with forced QUIC for localhost:$PORT" >&2
echo "  URL:        $URL" >&2
echo "  Profile:    $DATA_DIR (sandboxed; doesn't touch your real profile)" >&2
echo "  SPKI pin:   $SPKI_HASH (from $DEV_CERT)" >&2
echo "  Verify h3:  DevTools > Network > right-click columns > Protocol" >&2
echo >&2

exec "$APP" \
    --user-data-dir="$DATA_DIR" \
    --no-first-run \
    --no-default-browser-check \
    --origin-to-force-quic-on="localhost:$PORT" \
    --ignore-certificate-errors-spki-list="$SPKI_HASH" \
    "$URL"
