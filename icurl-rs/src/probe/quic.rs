use crate::evidence::{ErrorKind, Layer, ProbeResult, ProbeResultStatus};
use crate::probe::{BoxFuture, Probe, Target};
use crate::request::{Config as ReqConfig, Protocol as ReqProtocol, execute as request_execute};
use std::time::Duration;

pub struct QuicProbe;

impl Probe for QuicProbe {
    fn run<'a>(&'a self, target: &'a Target) -> BoxFuture<'a, ProbeResult> {
        Box::pin(async move {
            let mut result = ProbeResult::new("QUICHTTP3", Layer::Quic, &target.url.to_string());

            let mut response = None;
            let mut last_err = None;

            let ips = &target.ips;
            if ips.is_empty() {
                let req_cfg = ReqConfig {
                    url: target.url.to_string(),
                    host: target.host.clone(),
                    protocol: ReqProtocol::Http3Only,
                    max_time: Duration::from_secs(10),
                    connect_timeout: Duration::from_secs(5),
                    ..Default::default()
                };
                match request_execute(&req_cfg).await {
                    Ok(res) => response = Some(res),
                    Err(e) => last_err = Some(e.to_string()),
                }
            } else {
                for ip in ips {
                    let mut u = target.url.clone();
                    let _ = u.set_host(Some(&ip.to_string()));
                    let _ = u.set_port(Some(target.port));

                    let req_cfg = ReqConfig {
                        url: u.to_string(),
                        host: target.host.clone(),
                        protocol: ReqProtocol::Http3Only,
                        max_time: Duration::from_secs(10),
                        connect_timeout: Duration::from_secs(5),
                        ..Default::default()
                    };
                    match request_execute(&req_cfg).await {
                        Ok(res) => {
                            response = Some(res);
                            break;
                        }
                        Err(e) => {
                            last_err = Some(e.to_string());
                        }
                    }
                }
            }

            if let Some(res) = response {
                result.add_observation(&format!("HTTP/3 request succeeded over {}", res.protocol));
                result.finish(ProbeResultStatus::Ok, ErrorKind::None, "");
            } else {
                result.add_observation("HTTP/3 over QUIC did not complete");
                let err_str = last_err.unwrap_or_else(|| "QUIC/HTTP/3 request failed".to_string());
                let mut kind = ErrorKind::Unknown;
                let mut res_status = ProbeResultStatus::Failed;

                if err_str.contains("timeout") || err_str.contains("deadline") || err_str.contains("timed out") {
                    kind = ErrorKind::Timeout;
                    res_status = ProbeResultStatus::Timeout;
                } else if err_str.contains("refused") {
                    kind = ErrorKind::Refused;
                } else if err_str.contains("reset") {
                    kind = ErrorKind::Reset;
                } else if err_str.contains("certificate") || err_str.contains("cert") || err_str.contains("WebPki") {
                    kind = ErrorKind::Certificate;
                }

                result.finish(res_status, kind, &err_str);
            }

            result
        })
    }
}
