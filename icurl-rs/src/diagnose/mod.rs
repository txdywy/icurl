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
    dns: DnsProbe,
    pub probes: Vec<Box<dyn Probe>>,
    pub capture: Option<Box<dyn PacketCapture>>,
}

impl Default for DiagnoseEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagnoseEngine {
    pub fn new() -> Self {
        let tcp = Box::new(TcpProbe::new(std::time::Duration::from_secs(5)));
        let tls = Box::new(TlsProbe::new(std::time::Duration::from_secs(5), false));
        let http = Box::new(HttpProbe);
        let quic = Box::new(QuicProbe);

        let capture = Some(Box::new(crate::platform::macos::MacosCapture::new(".")) as Box<dyn PacketCapture>);

        Self {
            dns: DnsProbe::new(Box::new(DefaultResolver)),
            probes: vec![tcp, tls, http, quic],
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

        // Step 1: Run DNS probe first to populate target.ips
        let dns_res = self.dns.run_dns(&target).await;
        let mut all_results = vec![dns_res.probe_result];

        if all_results[0].result == ProbeResultStatus::Ok {
            target.ips = dns_res.resolved_ips;
        }

        // Step 2: Optionally start packet capture
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

        // Step 3: Run remaining probes in parallel
        let target_ref = &target;
        let futures: Vec<_> = self.probes.iter().enumerate().map(|(i, probe)| {
            async move {
                let res = probe.run(target_ref).await;
                (i, res)
            }
        }).collect();

        let other_results = join_all(futures).await;
        for (_, res) in other_results {
            all_results.push(res);
        }

        // Step 4: Stop capture
        if let Some(session) = capture_session {
            let _ = session.stop().await;
        }

        let assessment = classify(&all_results);

        DiagnoseResult {
            target: cfg.url.to_string(),
            probe_results: all_results,
            assessment,
            capture_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::BoxFuture as ProbeBoxFuture;
    use crate::probe::dns::{DnsProbe, Resolver};

    struct FakeResolver;
    impl Resolver for FakeResolver {
        fn lookup_ip<'a>(&'a self, _host: &'a str, _port: u16) -> ProbeBoxFuture<'a, std::io::Result<Vec<std::net::IpAddr>>> {
            Box::pin(async { Ok(vec!["127.0.0.1".parse().unwrap()]) })
        }
    }

    #[tokio::test]
    async fn test_diagnose_engine() {
        let engine = DiagnoseEngine {
            dns: DnsProbe::new(Box::new(FakeResolver)),
            probes: vec![],
            capture: None,
        };
        let url = Url::parse("https://example.com").unwrap();
        let result = engine.run(DiagnoseConfig { url, deep: false }).await;
        assert_eq!(result.probe_results.len(), 1);
        assert_eq!(result.probe_results[0].probe_name, "DNS");
    }
}
