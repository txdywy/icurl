# icurl

`icurl` is a diagnostics-first curl-like CLI for HTTP and HTTPS. It supports common request workflows and can explain failures across DNS, TCP, TLS, HTTP, UDP, and QUIC layers.

## Scope

The first version is curl-like, not a full curl clone. It focuses on HTTP/HTTPS, HTTP/1.1, HTTP/2, HTTP/3, and network diagnostics.

It does not provide proxy, VPN, tunnel, or censorship-circumvention functionality.

## Examples

```bash
icurl https://example.com
icurl -I https://example.com
icurl -i https://example.com
icurl -X POST -H 'Content-Type: application/json' -d '{}' https://example.com
icurl --http2 https://example.com
icurl --http3 https://example.com
icurl --http3-only https://example.com
icurl diagnose https://example.com
icurl diagnose --json https://example.com
icurl diagnose --deep https://example.com
```

## Deep diagnostics

`icurl diagnose --deep` uses `sudo /usr/sbin/tcpdump` on macOS to capture a short packet trace while probes run. Packet captures can contain sensitive data, so they are saved locally and never uploaded by `icurl`.

## Development

```bash
go test ./...
go build ./cmd/icurl
```
