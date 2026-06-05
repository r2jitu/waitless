// Shared client-side TLS / QUIC plumbing for the workloads.
//
// Every workload connects to the unikernel's self-signed dev cert, so
// they all bypass certificate verification (this measures throughput,
// not chain validation) and all resolve host:port the same way. Before
// this module each workload carried its own copy of `NoCertVerify` + a
// config builder + `resolve` — five near-identical copies. They live
// here once now.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;

/// Accept any server certificate — the unikernel ships a self-signed
/// dev cert and these workloads measure throughput, not validation.
#[derive(Debug)]
pub struct NoCertVerify;

impl rustls::client::danger::ServerCertVerifier for NoCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            ECDSA_NISTP256_SHA256,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PKCS1_SHA256,
        ]
    }
}

/// TLS 1.3 client config for the TCP path. `alpn` advertises the given
/// protocol identifiers (empty = none); `resumption` selects fresh
/// handshakes (`Resumption::disabled()`) vs the resumption hot path.
pub fn tcp_tls_config(alpn: &[&[u8]], resumption: Resumption) -> Arc<ClientConfig> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg.resumption = resumption;
    Arc::new(cfg)
}

/// QUIC client config (ALPN `h3`) with generous transport windows — the
/// workloads measure application-layer throughput, not flow control.
pub fn quic_client_config() -> quinn::ClientConfig {
    let mut tls_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerify))
        .with_no_client_auth();
    tls_cfg.alpn_protocols = vec![b"h3".to_vec()];

    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_cfg).expect("valid QUIC TLS config");
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(256u32.into())
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    cfg.transport_config(Arc::new(transport));
    cfg
}

/// Resolve `host:port`, preferring the first IPv4 result — `localhost`
/// resolves to v6 first on some glibc configs, but the unikernel
/// listens on v4.
pub fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    let mut addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
    addrs.sort_by_key(|a| match a {
        SocketAddr::V4(_) => 0,
        SocketAddr::V6(_) => 1,
    });
    addrs.into_iter().next()
}
