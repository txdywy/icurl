use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use crate::evidence::{ErrorKind, ProbeResult};

/// Attempt TCP connections to multiple addresses with a timeout.
/// Returns the first successful connection, or the last error.
pub async fn try_connect(
    ips: &[std::net::IpAddr],
    host: &str,
    port: u16,
    timeout_duration: Duration,
) -> Result<TcpStream, (ErrorKind, String)> {
    if !ips.is_empty() {
        let mut last_err = None;
        for ip in ips {
            let addr = SocketAddr::new(*ip, port);
            match timeout(timeout_duration, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some((ErrorKind::Unknown, e.to_string())),
                Err(_) => last_err = Some((ErrorKind::Timeout, "connection timed out".to_string())),
            }
        }
        Err(last_err.unwrap_or((ErrorKind::Unknown, "TCP connect failed".to_string())))
    } else {
        let addr = format!("{}:{}", host, port);
        match timeout(timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err((ErrorKind::Unknown, e.to_string())),
            Err(_) => Err((ErrorKind::Timeout, "connection timed out".to_string())),
        }
    }
}

/// Record remote/local addresses from a TcpStream into a ProbeResult.
pub fn record_addresses(stream: &TcpStream, result: &mut ProbeResult) {
    if let Ok(addr) = stream.peer_addr() {
        result.remote_address = Some(addr.to_string());
    }
    if let Ok(addr) = stream.local_addr() {
        result.local_address = Some(addr.to_string());
    }
}
