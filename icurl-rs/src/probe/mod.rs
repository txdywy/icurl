use std::net::IpAddr;
use url::Url;
use crate::evidence::ProbeResult;

pub mod dns;
pub mod tcp;
pub mod tls;
pub mod http;
pub mod quic;
pub mod tcp_connect;

#[derive(Debug, Clone)]
pub struct Target {
    pub url: Url,
    pub host: String,
    pub port: u16,
    pub ips: Vec<IpAddr>,
}

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub trait Probe: Send + Sync + 'static {
    fn probe_name(&self) -> &'static str;
    fn run<'a>(&'a self, target: &'a Target) -> BoxFuture<'a, ProbeResult>;
}
