use chrono::{DateTime, Utc};
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
            Layer::Dns => write!(f, "DNS"),
            Layer::Tcp => write!(f, "TCP"),
            Layer::Tls => write!(f, "TLS"),
            Layer::Http => write!(f, "HTTP"),
            Layer::Udp => write!(f, "UDP"),
            Layer::Quic => write!(f, "QUIC"),
            Layer::Local => write!(f, "LOCAL"),
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
            ProbeResultStatus::Ok => write!(f, "OK"),
            ProbeResultStatus::Failed => write!(f, "FAILED"),
            ProbeResultStatus::Timeout => write!(f, "TIMEOUT"),
            ProbeResultStatus::Skipped => write!(f, "SKIPPED"),
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
            ErrorKind::None => write!(f, "NONE"),
            ErrorKind::Timeout => write!(f, "TIMEOUT"),
            ErrorKind::Refused => write!(f, "REFUSED"),
            ErrorKind::Reset => write!(f, "RESET"),
            ErrorKind::Unreachable => write!(f, "UNREACHABLE"),
            ErrorKind::Certificate => write!(f, "CERTIFICATE"),
            ErrorKind::Protocol => write!(f, "PROTOCOL"),
            ErrorKind::SuspiciousDns => write!(f, "SUSPICIOUS_DNS"),
            ErrorKind::Permission => write!(f, "PERMISSION"),
            ErrorKind::Unknown => write!(f, "UNKNOWN"),
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
            AssessmentLevel::Pass => write!(f, "PASS"),
            AssessmentLevel::Fail => write!(f, "FAIL"),
            AssessmentLevel::SuspiciousLow => write!(f, "SUSPICIOUS_LOW"),
            AssessmentLevel::SuspiciousMedium => write!(f, "SUSPICIOUS_MEDIUM"),
            AssessmentLevel::SuspiciousHigh => write!(f, "SUSPICIOUS_HIGH"),
            AssessmentLevel::Unknown => write!(f, "UNKNOWN"),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    pub duration_ns: i64,
    pub result: ProbeResultStatus,
    pub error_kind: ErrorKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observations: Option<Vec<String>>,
    pub confidence: Confidence,
}

impl ProbeResult {
    pub fn new(probe_name: &str, layer: Layer, target: &str) -> Self {
        Self {
            probe_name: probe_name.to_string(),
            layer,
            target: target.to_string(),
            remote_address: None,
            local_address: None,
            started_at: Some(Utc::now()),
            finished_at: None,
            duration_ns: 0,
            result: ProbeResultStatus::Skipped,
            error_kind: ErrorKind::None,
            error_message: None,
            observations: None,
            confidence: Confidence::Observed,
        }
    }

    pub fn finish(&mut self, status: ProbeResultStatus, kind: ErrorKind, message: &str) {
        let now = Utc::now();
        if let Some(started) = self.started_at {
            self.duration_ns = (now - started).num_nanoseconds().unwrap_or(0);
        }
        self.finished_at = Some(now);
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
