# icurl Design

## Summary

`icurl` is a Go-based, diagnostics-first curl-like CLI for HTTP and HTTPS access. It supports common request workflows and HTTP/1.1, HTTP/2, and HTTP/3, then explains failures through layered DNS, TCP, TLS, HTTP, UDP, and QUIC diagnostics.

The first version targets macOS and prioritizes useful network failure evidence over full curl compatibility.

## Goals

- Provide a curl-like CLI for normal HTTP/HTTPS requests.
- Support HTTP/1.1, HTTP/2, and HTTP/3 in the first version.
- Diagnose failures below the HTTP application layer.
- Report structured evidence for DNS, TCP, TLS, HTTP, UDP, and QUIC behavior.
- Express suspected network interference through confidence levels, not absolute claims.
- Support an optional macOS deep-diagnose mode that uses `sudo` packet capture.
- Provide both human-readable and JSON output.

## Non-goals

- Full curl parameter compatibility in the first version.
- Non-HTTP protocols such as FTP, SFTP, SMTP, IMAP, or LDAP.
- Proxy, VPN, tunnel, or censorship-circumvention functionality.
- Windows deep diagnostic support in the first version.
- Automatic upload of packet captures or diagnostic artifacts.
- Absolute attribution that a failure was caused by a specific middlebox or firewall.

## Product Scope

The first release is a diagnostics-first curl-like tool.

Supported request features:

- URL input.
- `GET`, `POST`, and `HEAD`.
- Custom method via `-X` / `--request`.
- Custom headers via `-H` / `--header`.
- Request body via `-d` / `--data`.
- Header-only requests via `-I` / `--head`.
- Include response headers via `-i` / `--include`.
- Redirect following via `-L` / `--location`.
- Connection and total timeout controls.
- HTTP protocol selection with `--http1.1`, `--http2`, `--http3`, and `--http3-only`.
- Human-readable output by default.
- JSON output via `--json`.

Supported diagnostic modes:

- Automatic lightweight diagnostics after request failure.
- Explicit diagnostics with `icurl diagnose URL` or `--diagnose`.
- Optional deep diagnostics with `icurl diagnose --deep URL`.

## CLI Shape

Examples:

```bash
icurl https://example.com
icurl -I https://example.com
icurl -i https://example.com
icurl -X POST -H 'Content-Type: application/json' -d '{}' https://example.com
icurl --http1.1 https://example.com
icurl --http2 https://example.com
icurl --http3 https://example.com
icurl --http3-only https://example.com
icurl diagnose https://example.com
icurl diagnose --deep https://example.com
icurl diagnose --json https://example.com
```

`--http3` prefers HTTP/3 over QUIC but allows fallback to TCP/TLS with HTTP/2 or HTTP/1.1. `--http3-only` uses only QUIC/HTTP/3 and reports failure if that path fails.

## Architecture

```text
cmd/icurl
internal/cli
internal/request
internal/diagnose
internal/probe/dns
internal/probe/tcp
internal/probe/tls
internal/probe/http
internal/probe/quic
internal/evidence
internal/classifier
internal/report
internal/platform/macos
```

### CLI Layer

The CLI layer parses arguments and converts them into request and diagnostic configuration. It does not perform network operations directly.

Responsibilities:

- Parse commands, flags, and URLs.
- Build request configuration.
- Build diagnostic configuration.
- Select output format.
- Invoke request runner or diagnostic engine.

### Request Runner

The request runner performs normal HTTP requests and records timing and protocol metadata.

Responsibilities:

- Execute HTTP/1.1 and HTTP/2 requests using Go `net/http`.
- Execute HTTP/3 requests using `quic-go/http3`.
- Support protocol selection flags.
- Record status code, response headers, protocol version, redirect chain, and timing.
- Return structured request errors for the diagnostic engine.

HTTP/1.1 and HTTP/2 should use Go's standard HTTP stack. Custom transports must explicitly preserve HTTP/2 support when needed.

HTTP/3 should use `quic-go/http3`; the project should not implement QUIC itself.

### Diagnostic Engine

The diagnostic engine performs active probes and emits structured evidence. It is separate from the request runner so normal requests stay predictable and scriptable.

Probe sequence:

```text
URL parse
  ↓
DNS probe
  ↓
TCP probe
  ↓
TLS + ALPN probe
  ↓
HTTP/1.1 + HTTP/2 probe
  ↓
UDP/443 + QUIC + HTTP/3 probe
  ↓
optional packet capture
  ↓
evidence classifier
  ↓
human/json report
```

Default diagnostics may issue additional probes after a request fails. Explicit `diagnose` always runs the configured probe set.

### Evidence Model

Probes do not directly produce user-facing conclusions. They produce structured evidence.

Example fields:

```text
probe_name
layer
target
remote_address
local_address
started_at
finished_at
duration
result
error_kind
error_message
observations
confidence
```

Example evidence:

```text
Probe: TLSHandshake
Target: example.com:443
Layer: TLS
Result: failed
Error: connection reset before certificate
Observations:
  - TCP connect succeeded
  - ClientHello was sent with SNI example.com
  - no certificate was received
Confidence: observed
```

### Classifier

The classifier consumes evidence and produces assessments with confidence levels.

Assessment levels:

```text
PASS
FAIL
SUSPICIOUS_LOW
SUSPICIOUS_MEDIUM
SUSPICIOUS_HIGH
UNKNOWN
```

The classifier distinguishes observed facts from inferred explanations. It should avoid absolute attribution and instead report patterns such as DNS interference pattern, TLS/SNI interruption pattern, UDP/QUIC blockage pattern, local connectivity failure, or HTTP-layer origin failure.

### Report Renderer

The report renderer supports human-readable and JSON output.

Human-readable report example:

```text
Request failed: TLS handshake reset

Layer summary:
  DNS   OK       23ms
  TCP   OK       91ms
  TLS   FAIL     reset before certificate
  HTTP  SKIPPED  TLS failed
  QUIC  TIMEOUT  no UDP response

Assessment:
  Suspicious high: TLS/SNI interference pattern.

Evidence:
  - TCP connection to 203.0.113.10:443 succeeded.
  - TLS ClientHello with SNI example.com was sent.
  - Connection reset before any certificate was received.

Next steps:
  - Run `icurl diagnose --deep https://example.com` for packet-level evidence.
  - Compare with `--http3-only` if the site supports HTTP/3.
```

JSON output should be stable enough for scripts and future UI/report tooling.

## Diagnostic Probes

### DNS Probe

Collect:

- System resolver A and AAAA answers.
- Optional comparison resolver answers.
- Resolve duration.
- NXDOMAIN, SERVFAIL, timeout, empty answers.
- Private, reserved, loopback, multicast, or otherwise suspicious IP ranges.
- IPv4 and IPv6 differences.

Suspicious DNS signals include major divergence between system and comparison resolver results, reserved address answers for public domains, or DNS success paired with consistent connection failure to returned addresses.

### TCP Probe

Collect for each candidate IP and port:

- Connection success or failure.
- Timeout, refused, reset, unreachable, or other error kind.
- Connect latency.
- Local and remote addresses.

Interpretation:

- TCP timeout to all addresses suggests routing, firewall, packet drop, target unreachability, or local connectivity issues.
- TCP refused suggests a host or middlebox actively rejected the port.
- TCP success shifts suspicion to TLS, HTTP, or QUIC layers.

### TLS + ALPN Probe

Collect:

- SNI value.
- Offered ALPN protocols.
- Negotiated ALPN protocol.
- TLS version.
- Certificate chain summary.
- Certificate verification result.
- Whether the handshake failed before certificate receipt.
- Handshake latency.

Interpretation:

- TCP success plus reset or close before certificate receipt is a strong low-level signal.
- Certificate mismatch or untrusted root should be reported as certificate validation failure, not network interference.
- Successful TLS with HTTP 4xx or 5xx usually means the network path works and the failure is at the origin, CDN, WAF, policy, or application layer.

### HTTP/1.1 and HTTP/2 Probe

Collect after TLS succeeds:

- HTTP status.
- Protocol version.
- Redirect chain.
- Selected response headers.
- Unexpected EOF or malformed response errors.
- Lightweight body sample only when useful for diagnosing block pages or protocol anomalies.

Interpretation:

- HTTP responses prove the TLS and application path is reachable.
- HTTP 403, 429, or 5xx should not be classified as TCP/TLS network failure.
- Known block-page-like responses may be reported as HTTP-layer interception pattern with low or medium confidence.

### UDP, QUIC, and HTTP/3 Probe

Collect:

- UDP address resolution and dial result.
- QUIC handshake success or timeout.
- TLS 1.3 over QUIC success or failure.
- HTTP/3 request success or failure.
- Whether TCP/TLS succeeds while UDP/443 or QUIC fails.
- Whether the server advertises HTTP/3 through Alt-Svc when available.

Interpretation:

- TCP/TLS success plus repeated QUIC timeout suggests UDP/443 or QUIC path impairment, target HTTP/3 unavailability, or middlebox/NAT behavior.
- QUIC handshake success but HTTP/3 failure suggests server, protocol, or library compatibility issues.
- `--http3-only` should report only the QUIC/HTTP3 path.
- `--http3` should report both the HTTP/3 attempt and any fallback path.

### macOS Deep Diagnose

`icurl diagnose --deep URL` runs optional privileged diagnostics.

Behavior:

- Explain that deep diagnose needs `sudo` to run packet capture.
- Warn that packet captures may contain sensitive data.
- Start a short `tcpdump` capture.
- Run configured probes.
- Stop capture.
- Save a `.pcap` file locally.
- Report the pcap path.

The first version does not need to fully parse pcap files. It should reliably capture and preserve them for manual inspection or future automated analysis.

## Classification Rules

### DNS interference pattern

Conditions:

- System DNS answer differs significantly from comparison resolver results.
- System answer contains private, reserved, loopback, multicast, or otherwise suspicious addresses.
- TCP/TLS to system resolver addresses fails or behaves differently from comparison addresses.

Assessment:

- `SUSPICIOUS_MEDIUM` or `SUSPICIOUS_HIGH` depending on repeatability and address evidence.

### TLS/SNI interruption pattern

Conditions:

- TCP connect succeeds.
- TLS handshake resets or closes before certificate receipt.
- Failure is repeatable.
- Different SNI behavior can strengthen confidence when tested.

Assessment:

- `SUSPICIOUS_MEDIUM` or `SUSPICIOUS_HIGH`.

### UDP/QUIC blockage pattern

Conditions:

- TCP/443 succeeds.
- TLS and HTTP/2 succeed.
- QUIC or UDP/443 repeatedly times out.
- The user forced HTTP/3 or the server advertised HTTP/3.

Assessment:

- `SUSPICIOUS_MEDIUM` unless more evidence is available.

### Origin or application-layer failure

Conditions:

- DNS succeeds.
- TCP succeeds.
- TLS succeeds.
- HTTP returns 4xx, 5xx, or policy-like response.
- No low-level reset or timeout evidence exists.

Assessment:

- `FAIL` at HTTP layer.

### Local connectivity failure

Conditions:

- DNS fails for multiple targets, or TCP fails broadly.
- Interface, route, or gateway evidence indicates local network issues.
- Packet capture shows no outbound traffic or no replies across multiple control targets.

Assessment:

- `FAIL` at local connectivity layer.

### Evidence insufficient

Conditions:

- Probe results are contradictory.
- Only one weak signal is present.
- The failure is transient or not repeatable.

Assessment:

- `UNKNOWN` or `SUSPICIOUS_LOW` with recommended next steps.

## Milestones

### Milestone 1: Project skeleton and CLI foundation

Deliver:

- Go module.
- CLI framework.
- URL and flag parsing.
- Request configuration model.
- Diagnostic configuration model.
- Output mode selection.
- Shared error model.

Acceptance:

```bash
icurl https://example.com
icurl -I https://example.com
icurl -X POST -H 'Content-Type: application/json' -d '{}' https://example.com
```

### Milestone 2: HTTP/1.1 and HTTP/2 runner

Deliver:

- HTTP/1.1 and HTTP/2 request execution.
- `--http1.1` and `--http2`.
- Response header/body output.
- Redirect support.
- Timeout support.
- Basic timing metadata.

Acceptance:

```bash
icurl --http1.1 https://example.com
icurl --http2 https://example.com
icurl -i https://example.com
```

### Milestone 3: HTTP/3 and QUIC support

Deliver:

- HTTP/3 transport using `quic-go/http3`.
- `--http3` with fallback.
- `--http3-only` without fallback.
- HTTP/3 result reporting.

Acceptance:

```bash
icurl --http3 https://example.com
icurl --http3-only https://example.com
```

### Milestone 4: Lightweight diagnostics

Deliver:

- DNS probe.
- TCP probe.
- TLS probe.
- HTTP/1.1 and HTTP/2 probe.
- UDP/443 probe.
- QUIC and HTTP/3 probe.
- Automatic diagnostics after request failure.
- Explicit `diagnose` command.

Acceptance:

```bash
icurl diagnose https://example.com
icurl --diagnose https://example.com
```

### Milestone 5: Classifier and reports

Deliver:

- Evidence model.
- Probe result model.
- Assessment model.
- Classification rules.
- Human-readable report.
- JSON report.

Acceptance:

```bash
icurl diagnose --json https://example.com
```

### Milestone 6: macOS deep diagnose

Deliver:

- `icurl diagnose --deep URL`.
- Explicit sudo and privacy warning.
- Short tcpdump capture orchestration.
- Local pcap file output.
- Reported pcap path.

Acceptance:

```bash
icurl diagnose --deep https://example.com
```

## Testing Strategy

### Unit tests

Unit tests should not depend on external network state.

Cover:

- CLI parsing.
- Request config construction.
- URL normalization.
- Header parsing.
- Evidence construction.
- Classifier rules.
- Report rendering.
- JSON stability.

### Local integration tests

Use local controlled servers for:

- HTTP/1.1.
- HTTP/2 over TLS.
- HTTP/3 using quic-go.
- TLS certificate errors.
- TLS handshake interruption.
- HTTP redirects.
- HTTP 403 and 500.
- Slow responses.
- Early connection close.

### Real network smoke tests

Use only as optional smoke tests because external network behavior is not deterministic.

Examples:

```bash
icurl https://example.com
icurl --http2 https://example.com
icurl --http3 https://example.com
icurl diagnose https://example.com
```

## Risks and Mitigations

### Curl compatibility scope creep

Risk: full curl compatibility is too large for the first version.

Mitigation: document that the first version is curl-like, not a full curl clone. Add compatibility incrementally based on real usage.

### HTTP/3 complexity

Risk: HTTP/3 brings UDP, QUIC, TLS 1.3, ALPN, Alt-Svc, and fallback complexity.

Mitigation: use `quic-go/http3`; implement explicit `--http3` and `--http3-only` first; keep Alt-Svc cache out of the first core path.

### Misattribution of network interference

Risk: many unrelated failures can resemble censorship or middlebox behavior.

Mitigation: report evidence and confidence levels. Distinguish observed facts from inferred assessments. Avoid absolute claims.

### macOS privileges and privacy

Risk: packet capture requires sudo and may capture sensitive traffic.

Mitigation: require explicit `--deep`, show a privacy warning, keep captures short, save locally, and never upload artifacts.

### Flaky external tests

Risk: external websites, DNS, and network paths change.

Mitigation: keep core tests local and deterministic. Treat real network tests as optional smoke tests.

## References

- Go `net/http` documentation: https://pkg.go.dev/net/http
- quic-go HTTP/3 client documentation: https://quic-go.net/docs/http3/client/
- quic-go HTTP/3 documentation: https://quic-go.net/docs/http3/
- curl HTTP/3 documentation: https://curl.se/docs/http3.html
- Everything curl HTTP/3 guide: https://everything.curl.dev/http/versions/http3.html
- Apple packet trace guidance: https://developer.apple.com/documentation/network/submitting-a-packet-trace-to-apple
- Apple packet trace troubleshooting: https://developer.apple.com/documentation/network/troubleshooting-packet-traces
- Wireshark capture privileges: https://wiki.wireshark.org/CaptureSetup/CapturePrivileges
