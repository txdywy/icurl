pub mod macos;

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

pub trait CaptureSession: Send + Sync {
    fn stop(self: Box<Self>) -> BoxFuture<'static, std::io::Result<CompletedCapture>>;
}

pub struct CompletedCapture {
    pub path: String,
}

pub trait PacketCapture: Send + Sync {
    fn start(&self) -> BoxFuture<'_, std::io::Result<(String, Box<dyn CaptureSession>)>>;
}
