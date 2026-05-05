# Dev certificates

**DO NOT USE IN PRODUCTION.**

Pre-generated self-signed ECDSA P-256 certificate + private key for
local development and integration testing of the unikernel TLS server.

Files:

- `dev_cert.der` / `dev_cert.pem` — X.509 v3 self-signed certificate
- `dev_key.der` / `dev_key.pem`  — PKCS#8 ECDSA P-256 private key
- `regen.sh`                     — regeneration script

The `.der` files are what the unikernel server loads via `include_bytes!`.
The `.pem` files exist for `curl`, `openssl s_client`, and `wget` which
all accept PEM by default — use them when you're testing the server from
the host.

## Details

- Signature algorithm: **ECDSA with SHA-256 on NIST P-256** (TLS 1.3
  `sig_scheme 0x0403 = ecdsa_secp256r1_sha256`). We originally used
  Ed25519 (0x0807) — simpler and faster — but Chromium-family
  browsers (Chrome, Arc, Edge, Brave, ...) don't advertise ed25519 in
  their TLS 1.3 `signature_algorithms` extension for server auth, so
  they reject our CertVerify with `illegal_parameter(47)` and show
  `ERR_SSL_PROTOCOL_ERROR`. macOS's bundled LibreSSL also refuses
  Ed25519 signature verification. ECDSA P-256 is the first scheme in
  every modern client's preference list and works everywhere.
- Subject: `CN=unikernel.local, O=UniKernel Dev, OU=Development Only`
- SAN: `DNS:unikernel.local, DNS:localhost, IP:127.0.0.1, IP:10.0.2.15`
  covers the hostnames used by the `bazel run` HVF / QEMU user-mode
  networking paths, and the default HVF userspace-proxy IP.
- Validity: **10 years** from the day the cert was generated. We'll
  regenerate when we care about a cleaner CN or when the dev key
  rotates. For CI purposes this means no near-term expiry anxiety.

## Regenerate

Run `./regen.sh` from this directory, OR manually:

```bash
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt ec_param_enc:named_curve \
    -out dev_key.pem
openssl req -new -x509 -key dev_key.pem -out dev_cert.pem -days 3650 \
    -subj "/CN=unikernel.local/O=UniKernel Dev/OU=Development Only" \
    -addext "subjectAltName=DNS:unikernel.local,DNS:localhost,IP:127.0.0.1,IP:10.0.2.15" \
    -sha256
openssl pkey  -in dev_key.pem  -outform DER -out dev_key.der
openssl x509  -in dev_cert.pem -outform DER -out dev_cert.der
```

## Browser-trusted local cert via mkcert

The committed self-signed cert works for `curl --cacert` and host-side
test code, but Chrome/Safari/Edge will refuse it with a hard
`NET::ERR_CERT_AUTHORITY_INVALID` warning when you visit
`https://localhost:<port>` directly. To get a browser-trusted local
cert without giving up the same DER format, use [mkcert][mkcert]:

```bash
brew install mkcert nss          # nss is for Firefox; skip if you don't use it
mkcert -install                  # one-time: writes mkcert's local CA into the system keychain

apps/webserver/dev_certs/regen-mkcert.sh
bazel run //apps/webserver:run
```

`regen-mkcert.sh` overwrites `dev_cert.{pem,der}` and
`dev_key.{pem,der}` with an mkcert-issued ECDSA P-256 leaf (same
algorithm as the committed cert) signed by your local mkcert root.
Chrome trusts it because mkcert installed the root into the macOS
keychain. To revert to the committed self-signed cert,
`git checkout apps/webserver/dev_certs/dev_{cert,key}.{pem,der}`.

The mkcert-signed files are intentionally per-user — don't commit
them. The committed cert stays the canonical CI / fresh-checkout
path.

[mkcert]: https://github.com/FiloSottile/mkcert

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
