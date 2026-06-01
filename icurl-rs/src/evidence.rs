use std::time::Instant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Layer {
    #[serde(rename = "DNS")]
    Dns,
    #[serde(rename = "TCP")]
    Tcp,
    #[serde(rename = "TLS")]
    Tls,
    #[serde(rename = "HTTP")]
    Http,
    #[serde(rename = "UDP")]
    Udp,
    #[serde(rename = "QUIC")]
    Quic,
    #[serde(rename = "LOCAL")]
    Local,
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::Dns => f.write_str("DNS"),
            Layer::Tcp => f.write_str("TCP"),
            Layer::Tls => f.write_str("TLS"),
            Layer::Http => f.write_str("HTTP"),
            Layer::Udp => f.write_str("UDP"),
            Layer::Quic => f.write_str("QUIC"),
            Layer::Local => f.write_str("LOCAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeResultStatus {
    #[serde(rename = "OK")]
    Ok,
    #[serde(rename = "FAILED")]
    Failed,
    #[serde(rename = "TIMEOUT")]
    Timeout,
    #[serde(rename = "SKIPPED")]
    Skipped,
}

impl std::fmt::Display for ProbeResultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeResultStatus::Ok => f.write_str("OK"),
            ProbeResultStatus::Failed => f.write_str("FAILED"),
            ProbeResultStatus::Timeout => f.write_str("TIMEOUT"),
            ProbeResultStatus::Skipped => f.write_str("SKIPPED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ErrorKind {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "TIMEOUT")]
    Timeout,
    #[serde(rename = "REFUSED")]
    Refused,
    #[serde(rename = "RESET")]
    Reset,
    #[serde(rename = "UNREACHABLE")]
    Unreachable,
    #[serde(rename = "CERTIFICATE")]
    Certificate,
    #[serde(rename = "PROTOCOL")]
    Protocol,
    #[serde(rename = "SUSPICIOUS_DNS")]
    SuspiciousDns,
    #[serde(rename = "PERMISSION")]
    Permission,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::None => f.write_str("NONE"),
            ErrorKind::Timeout => f.write_str("TIMEOUT"),
            ErrorKind::Refused => f.write_str("REFUSED"),
            ErrorKind::Reset => f.write_str("RESET"),
            ErrorKind::Unreachable => f.write_str("UNREACHABLE"),
            ErrorKind::Certificate => f.write_str("CERTIFICATE"),
            ErrorKind::Protocol => f.write_str("PROTOCOL"),
            ErrorKind::SuspiciousDns => f.write_str("SUSPICIOUS_DNS"),
            ErrorKind::Permission => f.write_str("PERMISSION"),
            ErrorKind::Unknown => f.write_str("UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    #[serde(rename = "observed")]
    Observed,
    #[serde(rename = "inferred")]
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AssessmentLevel {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "SUSPICIOUS_LOW")]
    SuspiciousLow,
    #[serde(rename = "SUSPICIOUS_MEDIUM")]
    SuspiciousMedium,
    #[serde(rename = "SUSPICIOUS_HIGH")]
    SuspiciousHigh,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl std::fmt::Display for AssessmentLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssessmentLevel::Pass => f.write_str("PASS"),
            AssessmentLevel::Fail => f.write_str("FAIL"),
            AssessmentLevel::SuspiciousLow => f.write_str("SUSPICIOUS_LOW"),
            AssessmentLevel::SuspiciousMedium => f.write_str("SUSPICIOUS_MEDIUM"),
            AssessmentLevel::SuspiciousHigh => f.write_str("SUSPICIOUS_HIGH"),
            AssessmentLevel::Unknown => f.write_str("UNKNOWN"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_name: String,
    pub layer: Layer,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    pub duration_ns: u64,
    pub result: ProbeResultStatus,
    pub error_kind: ErrorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observations: Option<Vec<String>>,
    pub confidence: Confidence,
    #[serde(skip)]
    start_time: Option<Instant>,
}

impl ProbeResult {
    pub fn new(probe_name: &'static str, layer: Layer, target: &str) -> Self {
        Self {
            probe_name: probe_name.to_string(),
            layer,
            target: target.to_string(),
            remote_address: None,
            local_address: None,
            duration_ns: 0,
            result: ProbeResultStatus::Skipped,
            error_kind: ErrorKind::None,
            error_message: None,
            observations: None,
            confidence: Confidence::Observed,
            start_time: Some(Instant::now()),
        }
    }

    pub fn finish(&mut self, status: ProbeResultStatus, kind: ErrorKind, message: &str) {
        if let Some(start) = self.start_time.take() {
            self.duration_ns = start.elapsed().as_nanos() as u64;
        }
        self.result = status;
        self.error_kind = kind;
        if !message.is_empty() {
            self.error_message = Some(message.to_string());
        }
    }

    pub fn add_observation(&mut self, obs: &str) {
        self.observations
            .get_or_insert_with(Vec::new)
            .push(obs.to_string());
    }

    pub fn observations_list(&self) -> &[String] {
        self.observations.as_deref().unwrap_or(&[])
    }

    pub fn error_message_str(&self) -> &str {
        self.error_message.as_deref().unwrap_or("")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub level: AssessmentLevel,
    pub category: String,
    pub summary: String,
    pub reasons: Vec<String>,
    pub next_steps: Vec<String>,
}

/// Classify an error string into an ErrorKind + ProbeResultStatus.
/// Used by HTTP, QUIC, and TLS probes to avoid repeating the same match logic.
pub fn classify_error_string(err: &str) -> (ProbeResultStatus, ErrorKind) {
    if err.contains("timeout") || err.contains("deadline") || err.contains("timed out") {
        (ProbeResultStatus::Timeout, ErrorKind::Timeout)
    } else if err.contains("refused") {
        (ProbeResultStatus::Failed, ErrorKind::Refused)
    } else if err.contains("reset") {
        (ProbeResultStatus::Failed, ErrorKind::Reset)
    } else if err.contains("certificate") || err.contains("cert") || err.contains("WebPki") {
        (ProbeResultStatus::Failed, ErrorKind::Certificate)
    } else {
        (ProbeResultStatus::Failed, ErrorKind::Unknown)
    }
}
