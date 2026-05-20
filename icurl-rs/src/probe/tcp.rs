use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use crate::evidence::{ErrorKind, Layer, ProbeResult, ProbeResultStatus};
use crate::probe::{BoxFuture, Probe, Target};

pub struct TcpProbe {
    pub timeout: Duration,
}

impl TcpProbe {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Probe for TcpProbe {
    fn run<'a>(&'a self, target: &'a Target) -> BoxFuture<'a, ProbeResult> {
        Box::pin(async move {
            let address = format!("{}:{}", target.host, target.port);
            let mut result = ProbeResult::new("TCP", Layer::Tcp, &address);

            let timeout_duration = if self.timeout.is_zero() {
                Duration::from_secs(5)
            } else {
                self.timeout
            };

            let mut conn = None;
            let mut last_err = None;

            if !target.ips.is_empty() {
                for ip in &target.ips {
                    let addr = SocketAddr::new(*ip, target.port);
                    match timeout(timeout_duration, TcpStream::connect(addr)).await {
                        Ok(Ok(stream)) => {
                            conn = Some(stream);
                            break;
                        }
                        Ok(Err(e)) => {
                            last_err = Some((ErrorKind::Unknown, e.to_string()));
                        }
                        Err(_) => {
                            last_err = Some((ErrorKind::Timeout, "connection timed out".to_string()));
                        }
                    }
                }
            } else {
                match timeout(timeout_duration, TcpStream::connect(&address)).await {
                    Ok(Ok(stream)) => {
                        conn = Some(stream);
                    }
                    Ok(Err(e)) => {
                        last_err = Some((ErrorKind::Unknown, e.to_string()));
                    }
                    Err(_) => {
                        last_err = Some((ErrorKind::Timeout, "connection timed out".to_string()));
                    }
                }
            }

            if let Some(stream) = conn {
                if let Ok(addr) = stream.peer_addr() {
                    result.remote_address = Some(addr.to_string());
                }
                if let Ok(addr) = stream.local_addr() {
                    result.local_address = Some(addr.to_string());
                }
                result.add_observation("TCP connect succeeded");
                result.finish(ProbeResultStatus::Ok, ErrorKind::None, "");
            } else {
                let (kind, msg) = match last_err {
                    Some((k, m)) => (k, m),
                    _ => (ErrorKind::Unknown, "TCP connect failed".to_string()),
                };
                result.finish(ProbeResultStatus::Failed, kind, &msg);
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
