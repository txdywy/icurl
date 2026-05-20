use std::net::IpAddr;
use std::sync::OnceLock;
use ipnet::IpNet;
use crate::evidence::{ErrorKind, Layer, ProbeResult, ProbeResultStatus};
use crate::probe::{BoxFuture, Probe, Target};

pub trait Resolver: Send + Sync {
    fn lookup_ip<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>>;
}

pub struct DefaultResolver;

impl Resolver for DefaultResolver {
    fn lookup_ip<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, std::io::Result<Vec<IpAddr>>> {
        Box::pin(async move {
            let addr = format!("{}:{}", host, port);
            let addrs = tokio::net::lookup_host(&addr).await?;
            Ok(addrs.map(|s| s.ip()).collect())
        })
    }
}

pub struct DnsProbe {
    pub resolver: Box<dyn Resolver>,
}

impl DnsProbe {
    pub fn new(resolver: Box<dyn Resolver>) -> Self {
        Self { resolver }
    }
}

fn documentation_networks() -> &'static Vec<IpNet> {
    static NETWORKS: OnceLock<Vec<IpNet>> = OnceLock::new();
    NETWORKS.get_or_init(|| {
        vec![
            "192.0.2.0/24".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
            "203.0.113.0/24".parse().unwrap(),
        ]
    })
}

pub fn is_suspicious(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_private() {
                return true;
            }
            for net in documentation_networks() {
                if net.contains(&ip) {
                    return true;
                }
            }
        }
        IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            if (octets[0] & 0xfe) == 0xfc {
                return true;
            }
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return true;
            }
        }
    }
    false
}

impl Probe for DnsProbe {
    fn run<'a>(&'a self, target: &'a Target) -> BoxFuture<'a, ProbeResult> {
        Box::pin(async move {
            let mut result = ProbeResult::new("DNS", Layer::Dns, &target.host);
            
            let ips = if !target.ips.is_empty() {
                target.ips.clone()
            } else {
                match self.resolver.lookup_ip(&target.host, target.port).await {
                    Ok(resolved) => resolved,
                    Err(e) => {
                        result.finish(ProbeResultStatus::Failed, ErrorKind::Unknown, &e.to_string());
                        return result;
                    }
                }
            };

            if ips.is_empty() {
                result.finish(ProbeResultStatus::Failed, ErrorKind::Unknown, "resolver returned no addresses");
                return result;
            }

            for ip in ips {
                result.add_observation(&format!("resolved {}", ip));
                if is_suspicious(ip) {
                    result.finish(
                        ProbeResultStatus::Failed,
                        ErrorKind::SuspiciousDns,
                        &format!("resolver returned suspicious address {}", ip),
                    );
                    return result;
                }
            }

            result.finish(ProbeResultStatus::Ok, ErrorKind::None, "");
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct FakeResolver {
        ips: Vec<IpAddr>,
        err: Option<io::Error>,
    }

    impl Resolver for FakeResolver {
        fn lookup_ip<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, io::Result<Vec<IpAddr>>> {
            Box::pin(async move {
                if let Some(ref e) = self.err {
                    Err(io::Error::new(e.kind(), e.to_string()))
                } else {
                    Ok(self.ips.clone())
                }
            })
        }
    }

    #[tokio::test]
    async fn test_dns_probe_suspicious() {
        let resolver = FakeResolver {
            ips: vec!["203.0.113.10".parse().unwrap()],
            err: None,
        };
        let probe = DnsProbe::new(Box::new(resolver));
        let target = Target {
            url: url::Url::parse("https://example.com").unwrap(),
            host: "example.com".to_string(),
            port: 443,
            ips: vec![],
        };
        let res = probe.run(&target).await;
        assert_eq!(res.result, ProbeResultStatus::Failed);
        assert_eq!(res.error_kind, ErrorKind::SuspiciousDns);
    }

    #[tokio::test]
    async fn test_dns_probe_ok() {
        let resolver = FakeResolver {
            ips: vec!["93.184.216.34".parse().unwrap()],
            err: None,
        };
        let probe = DnsProbe::new(Box::new(resolver));
        let target = Target {
            url: url::Url::parse("https://example.com").unwrap(),
            host: "example.com".to_string(),
            port: 443,
            ips: vec![],
        };
        let res = probe.run(&target).await;
        assert_eq!(res.result, ProbeResultStatus::Ok);
        assert_eq!(res.error_kind, ErrorKind::None);
    }
}
