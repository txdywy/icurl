use std::process::Stdio;
use tokio::process::Command;
use std::time::SystemTime;

use crate::platform::{PacketCapture, CaptureSession, CompletedCapture, BoxFuture};

pub struct MacosCapture {
    pub output_dir: String,
}

impl MacosCapture {
    pub fn new(output_dir: &str) -> Self {
        Self {
            output_dir: output_dir.to_string(),
        }
    }
}

struct MacosCaptureSession {
    child: tokio::process::Child,
    path: String,
}

impl CaptureSession for MacosCaptureSession {
    fn stop(mut self: Box<Self>) -> BoxFuture<'static, std::io::Result<CompletedCapture>> {
        Box::pin(async move {
            if let Some(id) = self.child.id() {
                let mut kill = std::process::Command::new("kill")
                    .arg("-INT")
                    .arg(id.to_string())
                    .spawn()?;
                let _ = kill.wait();
            }
            let _ = self.child.wait().await;
            Ok(CompletedCapture { path: self.path })
        })
    }
}

impl PacketCapture for MacosCapture {
    fn start(&self) -> BoxFuture<'_, std::io::Result<(String, Box<dyn CaptureSession>)>> {
        Box::pin(async move {
            let output_dir = if self.output_dir.is_empty() {
                ".".to_string()
            } else {
                self.output_dir.clone()
            };

            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let filename = format!("icurl-trace-{}.pcap", timestamp);
            let path = std::path::Path::new(&output_dir)
                .join(filename)
                .to_string_lossy()
                .to_string();

            let child = Command::new("sudo")
                .args(["/usr/sbin/tcpdump", "-i", "any", "-s", "0", "-w", &path])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;

            let session: Box<dyn CaptureSession> = Box::new(MacosCaptureSession { child, path: path.clone() });
            Ok((path, session))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeCaptureSession {
        path: String,
    }

    impl CaptureSession for FakeCaptureSession {
        fn stop(self: Box<Self>) -> BoxFuture<'static, std::io::Result<CompletedCapture>> {
            Box::pin(async move {
                Ok(CompletedCapture { path: self.path })
            })
        }
    }

    struct FakeCapture;

    impl PacketCapture for FakeCapture {
        fn start(&self) -> BoxFuture<'_, std::io::Result<(String, Box<dyn CaptureSession>)>> {
            Box::pin(async move {
                let session: Box<dyn CaptureSession> = Box::new(FakeCaptureSession { path: "trace.pcap".to_string() });
                Ok((
                    "trace.pcap".to_string(),
                    session,
                ))
            })
        }
    }

    #[tokio::test]
    async fn test_fake_capture() {
        let capture = FakeCapture;
        let (path, session) = capture.start().await.unwrap();
        assert_eq!(path, "trace.pcap");
        let completed = session.stop().await.unwrap();
        assert_eq!(completed.path, "trace.pcap");
    }
}
