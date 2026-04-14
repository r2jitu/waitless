# Dev certificates

**DO NOT USE IN PRODUCTION.**

Pre-generated self-signed Ed25519 certificate + private key for local
development and integration testing of the unikernel TLS / QUIC server.

Files:

- `dev_cert.der` / `dev_cert.pem` — X.509 v3 self-signed CA certificate
- `dev_key.der` / `dev_key.pem`  — PKCS#8 Ed25519 private key
- `regen.sh`                     — regeneration script

The `.der` files are what the unikernel server loads via `include_bytes!`.
The `.pem` files exist for `curl`, `openssl s_client`, and `wget` which
all accept PEM by default — use them when you're testing the server from
the host.

## Details

- Signature algorithm: **Ed25519** (no per-handshake randomness dance
  like ECDSA, compact 32-byte keys, fastest pure-Rust verification in
  the rustls-rustcrypto provider)
- Subject: `CN=unikernel.local, O=UniKernel Dev, OU=Development Only`
- SAN: `DNS:unikernel.local, DNS:localhost, IP:127.0.0.1, IP:10.0.2.15`
  covers the hostnames used by `run-local.sh` HVF / QEMU user-mode
  networking, and the default HVF userspace-proxy IP.
- Validity: **10 years** from the day the cert was generated. We'll
  regenerate when we care about a cleaner CN or when the dev key
  rotates. For CI purposes this means no near-term expiry anxiety.

## Regenerate

Run `./regen.sh` from this directory, OR manually:

```bash
openssl genpkey -algorithm ED25519 -out dev_key.pem
openssl req -new -x509 -key dev_key.pem -out dev_cert.pem -days 3650 \
    -subj "/CN=unikernel.local/O=UniKernel Dev/OU=Development Only" \
    -addext "subjectAltName=DNS:unikernel.local,DNS:localhost,IP:127.0.0.1,IP:10.0.2.15"
openssl pkey  -in dev_key.pem  -outform DER -out dev_key.der
openssl x509  -in dev_cert.pem -outform DER -out dev_cert.der
```

## Why we check in the cert instead of generating at boot

We'll eventually want a proper RNG in the kernel (jitter + RDRAND +
reseeded ChaCha) so production builds can generate ephemeral keys at
boot. Until then, a stable checked-in dev cert:

1. Keeps CI deterministic — the same cert bytes build every time,
   tests don't need an RNG.
2. Lets `curl --cacert apps/webserver/dev_certs/dev_cert.pem https://...`
   work straight out of a fresh checkout without `-k`.
3. Is trivially regeneratable (`regen.sh`), so rotation is cheap.

See `ROADMAP.md` → "Deferred" for the production cert / RNG work.

## Host test commands

```bash
# wrk-style throughput bench against TLS endpoint (future)
curl --cacert apps/webserver/dev_certs/dev_cert.pem https://localhost:8443/health

# raw TLS 1.3 handshake + cipher / group dump
openssl s_client -connect localhost:8443 -tls1_3 \
    -CAfile apps/webserver/dev_certs/dev_cert.pem -servername unikernel.local
```
