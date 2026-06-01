use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsConnector;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid, ServerCertVerified};
use rustls::{DigitallySignedStruct, SignatureScheme, Error as RustlsError};

use crate::evidence::{classify_error_string, ErrorKind, Layer, ProbeResult, ProbeResultStatus};
use crate::probe::{BoxFuture, Probe, Target};
use crate::probe::tcp_connect::{try_connect, record_addresses};
use tokio::time::timeout;

#[derive(Debug)]
struct DummyVerifier;

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub struct TlsProbe {
    pub timeout: Duration,
    pub insecure_skip_verify: bool,
}

impl TlsProbe {
    pub fn new(timeout: Duration, insecure_skip_verify: bool) -> Self {
        Self {
            timeout,
            insecure_skip_verify,
        }
    }
}

impl Probe for TlsProbe {
    fn probe_name(&self) -> &'static str { "TLS" }

    fn run<'a>(&'a self, target: &'a Target) -> BoxFuture<'a, ProbeResult> {
        Box::pin(async move {
            let address = format!("{}:{}", target.host, target.port);
            let mut result = ProbeResult::new("TLS", Layer::Tls, &address);

            let timeout_duration = if self.timeout.is_zero() {
                Duration::from_secs(5)
            } else {
                self.timeout
            };

            // 1. TCP Connect (shared logic)
            let tcp_stream = match try_connect(&target.ips, &target.host, target.port, timeout_duration).await {
                Ok(stream) => stream,
                Err((kind, msg)) => {
                    result.finish(ProbeResultStatus::Failed, kind, &msg);
                    return result;
                }
            };

            record_addresses(&tcp_stream, &mut result);

            // 2. Setup TLS Config
            let server_name = match ServerName::try_from(target.host.clone()) {
                Ok(name) => name,
                Err(e) => {
                    result.finish(ProbeResultStatus::Failed, ErrorKind::Unknown, &format!("invalid server name: {}", e));
                    return result;
                }
            };

            let config = if self.insecure_skip_verify {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(DummyVerifier))
                    .with_no_client_auth()
            } else {
                let mut root_store = rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let mut c = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                c
            };

            let connector = TlsConnector::from(Arc::new(config));

            // 3. TLS Handshake
            match timeout(timeout_duration, connector.connect(server_name, tcp_stream)).await {
                Ok(Ok(tls_stream)) => {
                    let (_, connection) = tls_stream.into_inner();
                    let alpn = connection.alpn_protocol()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                        .unwrap_or_default();
                    result.add_observation("TLS handshake succeeded");
                    if !alpn.is_empty() {
                        result.add_observation(&format!("ALPN {}", alpn));
                    }
                    result.finish(ProbeResultStatus::Ok, ErrorKind::None, "");
                }
                Ok(Err(e)) => {
                    result.add_observation("TLS handshake did not complete");
                    let err_str = e.to_string();

                    if e.kind() == std::io::ErrorKind::TimedOut {
                        result.finish(ProbeResultStatus::Timeout, ErrorKind::Timeout, &err_str);
                    } else if err_str.contains("certificate") || err_str.contains("cert") || err_str.contains("WebPki") {
                        result.finish(ProbeResultStatus::Failed, ErrorKind::Certificate, &err_str);
                    } else {
                        let (status, kind) = classify_error_string(&err_str);
                        result.finish(status, kind, &err_str);
                    }
                }
                Err(_) => {
                    result.add_observation("TLS handshake did not complete");
                    result.finish(
                        ProbeResultStatus::Timeout,
                        ErrorKind::Timeout,
                        "TLS handshake timed out",
                    );
                }
            }

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tls_probe_connect_fail() {
        let target = Target {
            url: url::Url::parse("https://example.invalid").unwrap(),
            host: "127.0.0.1".to_string(),
            port: 12345,
            ips: vec![],
        };

        let probe = TlsProbe::new(Duration::from_millis(50), false);
        let res = probe.run(&target).await;
        assert_eq!(res.result, ProbeResultStatus::Failed);
    }
}
