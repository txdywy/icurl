use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{redirect, Client, Method, Version};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Auto,
    Http11,
    Http2,
    Http3,
    Http3Only,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub host: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub head: bool,
    pub include_headers: bool,
    pub follow_redirect: bool,
    pub connect_timeout: Duration,
    pub max_time: Duration,
    pub protocol: Protocol,
    pub diagnose: bool,
    pub json_output: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            url: String::new(),
            host: String::new(),
            method: String::new(),
            headers: Vec::new(),
            body: String::new(),
            head: false,
            include_headers: false,
            follow_redirect: false,
            connect_timeout: Duration::from_secs(10),
            max_time: Duration::from_secs(30),
            protocol: Protocol::Auto,
            diagnose: false,
            json_output: false,
        }
    }
}

impl Config {
    pub fn effective_method(&self) -> Method {
        if self.head {
            return Method::HEAD;
        }
        if !self.method.is_empty() {
            return Method::from_bytes(self.method.to_uppercase().as_bytes())
                .unwrap_or(Method::GET);
        }
        if !self.body.is_empty() {
            return Method::POST;
        }
        Method::GET
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Redirect {
    pub from: String,
    pub to: String,
    pub status_code: u16,
}

#[derive(Debug)]
pub struct RequestResult {
    pub url: String,
    pub status_code: u16,
    pub protocol: String,
    pub response_headers: BTreeMap<String, Vec<String>>,
    pub body: Vec<u8>,
    pub redirects: Vec<Redirect>,
    pub timing_total_ms: u128,
}

pub async fn execute(cfg: &Config) -> Result<RequestResult> {
    let started = std::time::Instant::now();

    let redirect_policy = if cfg.follow_redirect {
        redirect::Policy::limited(10)
    } else {
        redirect::Policy::none()
    };

    let mut client_builder = Client::builder()
        .redirect(redirect_policy)
        .connect_timeout(cfg.connect_timeout)
        .timeout(cfg.max_time)
        .danger_accept_invalid_certs(false);

    let mut target_url = cfg.url.clone();

    // When URL host is an IP, resolve it to the real hostname for proper SNI/Host header
    if !cfg.host.is_empty() {
        if let Ok(mut parsed_url) = url::Url::parse(&cfg.url) {
            if let Some(host_str) = parsed_url.host_str() {
                if let Ok(ip) = host_str.parse::<std::net::IpAddr>() {
                    let port = parsed_url.port().unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });
                    let socket_addr = std::net::SocketAddr::new(ip, port);
                    client_builder = client_builder.resolve(&cfg.host, socket_addr);
                    let _ = parsed_url.set_host(Some(&cfg.host));
                    target_url = parsed_url.to_string();
                }
            }
        }
    }

    match cfg.protocol {
        Protocol::Http11 => { client_builder = client_builder.http1_only(); }
        Protocol::Http2 => { client_builder = client_builder.http2_prior_knowledge(); }
        Protocol::Http3 | Protocol::Http3Only => { client_builder = client_builder.http3_prior_knowledge(); }
        Protocol::Auto => {}
    }

    let client = client_builder.build()?;

    let method = cfg.effective_method();
    let mut request_builder = client.request(method, &target_url);

    if !cfg.host.is_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_str(&cfg.host)?,
        );
        request_builder = request_builder.headers(headers);
    }

    for (name, value) in &cfg.headers {
        request_builder = request_builder.header(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }

    if !cfg.body.is_empty() {
        request_builder = request_builder.body(cfg.body.clone());
    }

    let response = request_builder.send().await?;

    let status_code = response.status().as_u16();
    let protocol = match response.version() {
        Version::HTTP_09 => "HTTP/0.9".to_string(),
        Version::HTTP_10 => "HTTP/1.0".to_string(),
        Version::HTTP_11 => "HTTP/1.1".to_string(),
        Version::HTTP_2 => "HTTP/2.0".to_string(),
        Version::HTTP_3 => "HTTP/3.0".to_string(),
        _ => "HTTP/?".to_string(),
    };
    let url = response.url().to_string();

    let mut response_headers = BTreeMap::new();
    for (name, value) in response.headers().iter() {
        let entry = response_headers
            .entry(name.to_string())
            .or_insert_with(Vec::new);
        if let Ok(v) = value.to_str() {
            entry.push(v.to_string());
        }
    }

    let body = response.bytes().await?.to_vec();
    let timing_total_ms = started.elapsed().as_millis();

    Ok(RequestResult {
        url,
        status_code,
        protocol,
        response_headers,
        body,
        redirects: Vec::new(),
        timing_total_ms,
    })
}
