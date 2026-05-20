use crate::evidence::{Assessment, ProbeResult, ProbeResultStatus};
use crate::probe::{
    dns::{DefaultResolver, DnsProbe},
    http::HttpProbe,
    quic::QuicProbe,
    tcp::TcpProbe,
    tls::TlsProbe,
    Probe, Target,
};
use crate::platform::{PacketCapture, CaptureSession};
use crate::classifier::classify;
use url::Url;
use std::net::IpAddr;
use futures::future::join_all;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct DiagnoseConfig {
    pub url: Url,
    pub deep: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnoseResult {
    pub target: String,
    pub probe_results: Vec<ProbeResult>,
    pub assessment: Assessment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_path: Option<String>,
}

pub struct DiagnoseEngine {
    pub probes: Vec<Box<dyn Probe>>,
    pub capture: Option<Box<dyn PacketCapture>>,
}

impl DiagnoseEngine {
    pub fn new() -> Self {
        let dns = Box::new(DnsProbe::new(Box::new(DefaultResolver)));
        let tcp = Box::new(TcpProbe::new(std::time::Duration::from_secs(5)));
        let tls = Box::new(TlsProbe::new(std::time::Duration::from_secs(5), false));
        let http = Box::new(HttpProbe);
        let quic = Box::new(QuicProbe);

        let capture = Some(Box::new(crate::platform::macos::MacosCapture::new(".")) as Box<dyn PacketCapture>);

        Self {
            probes: vec![dns, tcp, tls, http, quic],
            capture,
        }
    }

    pub async fn run(&self, cfg: DiagnoseConfig) -> DiagnoseResult {
        let scheme = cfg.url.scheme();
        let port = cfg.url.port().unwrap_or(if scheme == "http" { 80 } else { 443 });
        let host = cfg.url.host_str().unwrap_or("").to_string();

        let mut target = Target {
            url: cfg.url.clone(),
            host: host.clone(),
            port,
            ips: Vec::new(),
        };

        let mut probe_results = vec![None; self.probes.len()];

        let mut dns_index = None;
        for (i, _probe) in self.probes.iter().enumerate() {
            // A run with target is needed to detect name or we can identify by some signature.
            // But we can check probe_results name by running a dummy Target or just by looking at a temporary target.
            let dummy_target = Target {
                url: Url::parse("http://localhost").unwrap(),
                host: "localhost".to_string(),
                port: 80,
                ips: Vec::new(),
            };
            if self.probes[i].run(&dummy_target).await.probe_name == "DNS" {
                dns_index = Some(i);
                break;
            }
        }

        if let Some(idx) = dns_index {
            let dns_res = self.probes[idx].run(&target).await;
            if dns_res.result == ProbeResultStatus::Ok {
                let mut ips = Vec::new();
                if let Some(ref obs) = dns_res.observations {
                    for o in obs {
                        if o.starts_with("resolved ") {
                            let ip_str = o.trim_start_matches("resolved ");
                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                ips.push(ip);
                            }
                        }
                    }
                }
                target.ips = ips;
            }
            probe_results[idx] = Some(dns_res);
        } else {
            if let Ok(addrs) = tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                target.ips = addrs.map(|s| s.ip()).collect();
            }
        }

        let mut capture_path = None;
        let mut capture_session: Option<Box<dyn CaptureSession>> = None;
        if cfg.deep {
            if let Some(ref capture) = self.capture {
                if let Ok((path, session)) = capture.start().await {
                    capture_path = Some(path);
                    capture_session = Some(session);
                }
            }
        }

        let target_ref = &target;
        let mut futures = Vec::new();
        for (i, probe) in self.probes.iter().enumerate() {
            if dns_index == Some(i) {
                continue;
            }
            futures.push(async move {
                let res = probe.run(target_ref).await;
                (i, res)
            });
        }

        let other_results = join_all(futures).await;
        for (i, res) in other_results {
            probe_results[i] = Some(res);
        }

        if let Some(session) = capture_session {
            let _ = session.stop().await;
        }

        let final_results: Vec<ProbeResult> = probe_results.into_iter().flatten().collect();
        let assessment = classify(&final_results);

        DiagnoseResult {
            target: cfg.url.to_string(),
            probe_results: final_results,
            assessment,
            capture_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProbe;

    impl Probe for FakeProbe {
        fn run<'a>(&'a self, _target: &'a Target) -> crate::probe::BoxFuture<'a, ProbeResult> {
            Box::pin(async move {
                let mut res = ProbeResult::new("DNS", crate::evidence::Layer::Dns, "localhost");
                res.result = ProbeResultStatus::Ok;
                res.add_observation("resolved 127.0.0.1");
                res
            })
        }
    }

    #[tokio::test]
    async fn test_diagnose_engine() {
        let engine = DiagnoseEngine {
            probes: vec![Box::new(FakeProbe)],
            capture: None,
        };
        let url = Url::parse("https://example.com").unwrap();
        let result = engine.run(DiagnoseConfig { url, deep: false }).await;
        assert_eq!(result.probe_results.len(), 1);
        assert_eq!(result.probe_results[0].probe_name, "DNS");
    }
}
