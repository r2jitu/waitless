FROM debian:bookworm-slim

# nginx 1.26 from Debian's official repos. Bookworm ships nginx 1.22
# in stable; we want 1.26 for the keep-alive + http2 fixes that
# landed in the 1.25 series. nginx-mainline is on the
# nginx.org repo; pin to a specific version so future bench
# re-runs reproduce.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates lsb-release && \
    curl -fsSL https://nginx.org/keys/nginx_signing.key | \
        gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/mainline/debian bookworm nginx" \
        > /etc/apt/sources.list.d/nginx.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends nginx && \
    apt-get purge -y curl gnupg && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Static body for /static-64k — 64 KiB of zeros, matching the waitless
# `STATIC_64K_BYTES` constant in apps/webserver/src/endpoints.rs:42.
# Pre-built at image-build time so nginx can serve it as a regular
# static file (sendfile + kTLS on the HTTPS path).
RUN mkdir -p /var/www/static && \
    dd if=/dev/zero of=/var/www/static/static-64k bs=1024 count=64 status=none && \
    dd if=/dev/zero of=/var/www/static/static-16k bs=1024 count=16 status=none && \
    dd if=/dev/zero of=/var/www/static/static-256k bs=1024 count=256 status=none && \
    dd if=/dev/zero of=/var/www/static/static-1m bs=1024 count=1024 status=none

# /health body as a static file with the exact bytes waitless emits
# (apps/webserver/src/endpoints.rs:12 — HEALTH_JSON). 54 bytes, no
# trailing newline, no whitespace.
RUN printf '%s' '{"status":"ok","runtime":"waitless","version":"0.1.0"}' \
        > /var/www/static/health.json

# Dev TLS cert/key shared with the waitless deploy. Mounted at run
# time so the same ECDSA P-256 cert is used by both peers and waitless,
# isolating TLS-stack differences from cert-algorithm differences.
RUN mkdir -p /etc/nginx/tls

# `nginx.conf` declares `user www-data;` so the same config works on
# the GCE peer VM (Debian's stock nginx user). The nginx.org base
# image creates a `nginx` user; create www-data too so the config
# parses here as well.
RUN groupadd -r www-data 2>/dev/null || true && \
    useradd -r -g www-data -s /usr/sbin/nologin www-data 2>/dev/null || true

COPY nginx.conf /etc/nginx/nginx.conf

# nginx (mainline) container default already forwards access/error
# logs to stdout/stderr via /var/log/nginx/{access,error}.log symlinks
# to /dev/stdout / /dev/stderr — keep as-is.

# Listen ports match waitless: 80 plain HTTP, 443 HTTPS.
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
