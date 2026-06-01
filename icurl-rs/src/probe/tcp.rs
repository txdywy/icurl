use std::time::Duration;
use crate::evidence::{ErrorKind, Layer, ProbeResult, ProbeResultStatus};
use crate::probe::{BoxFuture, Probe, Target};
use crate::probe::tcp_connect::{try_connect, record_addresses};

pub struct TcpProbe {
    pub timeout: Duration,
}

impl TcpProbe {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Probe for TcpProbe {
    fn probe_name(&self) -> &'static str { "TCP" }

    fn run<'a>(&'a self, target: &'a Target) -> BoxFuture<'a, ProbeResult> {
        Box::pin(async move {
            let address = format!("{}:{}", target.host, target.port);
            let mut result = ProbeResult::new("TCP", Layer::Tcp, &address);

            let timeout_duration = if self.timeout.is_zero() {
                Duration::from_secs(5)
            } else {
                self.timeout
            };

            match try_connect(&target.ips, &target.host, target.port, timeout_duration).await {
                Ok(stream) => {
                    record_addresses(&stream, &mut result);
                    result.add_observation("TCP connect succeeded");
                    result.finish(ProbeResultStatus::Ok, ErrorKind::None, "");
                }
                Err((kind, msg)) => {
                    result.finish(ProbeResultStatus::Failed, kind, &msg);
                }
            }

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_probe_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let target = Target {
            url: url::Url::parse("https://example.com").unwrap(),
            host: addr.ip().to_string(),
            port: addr.port(),
            ips: vec![addr.ip()],
        };

        let probe = TcpProbe::new(Duration::from_secs(1));
        let res = probe.run(&target).await;
        assert_eq!(res.result, ProbeResultStatus::Ok);
        assert_eq!(res.error_kind, ErrorKind::None);
        assert!(res.remote_address.is_some());
    }
}
