package diagnose

import (
	"context"
	"net/url"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type fakeProbe struct {
	result evidence.ProbeResult
	target probe.Target
}

func (p *fakeProbe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	_ = ctx
	p.target = target
	return p.result
}

type fakeCapture struct {
	started bool
}

func (c *fakeCapture) Start(ctx context.Context) (string, func() error, error) {
	_ = ctx
	c.started = true
	return "trace.pcap", func() error { return nil }, nil
}

func TestEngineRunsProbesAndClassifiesTLSInterruption(t *testing.T) {
	parsed, err := url.Parse("https://example.com/path")
	if err != nil {
		t.Fatal(err)
	}
	tcpProbe := &fakeProbe{result: evidence.ProbeResult{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone}}
	tlsProbe := &fakeProbe{result: evidence.ProbeResult{ProbeName: "tls", Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorReset}}
	engine := Engine{Probes: []probe.Probe{tcpProbe, tlsProbe}}

	result := engine.Run(context.Background(), Config{URL: parsed})

	if result.Target != "https://example.com/path" {
		t.Fatalf("unexpected target: %q", result.Target)
	}
	if len(result.ProbeResults) != 2 {
		t.Fatalf("expected 2 probe results, got %d", len(result.ProbeResults))
	}
	if result.Assessment.Category != "TLS_SNI_INTERRUPTION_PATTERN" {
		t.Fatalf("unexpected assessment category: %q", result.Assessment.Category)
	}
	if tcpProbe.target.Host != "example.com" || tcpProbe.target.Port != "443" {
		t.Fatalf("unexpected target host/port: %s:%s", tcpProbe.target.Host, tcpProbe.target.Port)
	}
	// IPs may be populated now since we resolve DNS in the engine
}

func TestEngineHandlesMissingURL(t *testing.T) {
	engine := Engine{Probes: []probe.Probe{&fakeProbe{}}}

	result := engine.Run(context.Background(), Config{})

	if result.Assessment.Level != evidence.AssessmentUnknown {
		t.Fatalf("unexpected assessment level: %q", result.Assessment.Level)
	}
	if result.Assessment.Category != "INSUFFICIENT_EVIDENCE" {
		t.Fatalf("unexpected assessment category: %q", result.Assessment.Category)
	}
	if result.Assessment.Summary != "diagnostic URL is missing" {
		t.Fatalf("unexpected summary: %q", result.Assessment.Summary)
	}
	if len(result.ProbeResults) != 0 {
		t.Fatalf("expected no probe results, got %d", len(result.ProbeResults))
	}
}

func TestEngineUsesExplicitPort(t *testing.T) {
	parsed, err := url.Parse("http://example.com:8080")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProbe{result: evidence.ProbeResult{ProbeName: "tcp", Layer: evidence.LayerTCP, Result: evidence.ResultOK, ErrorKind: evidence.ErrorNone}}
	engine := Engine{Probes: []probe.Probe{p}}

	engine.Run(context.Background(), Config{URL: parsed})

	if p.target.Port != "8080" {
		t.Fatalf("unexpected port: %q", p.target.Port)
	}
}

func TestEngineStartsCaptureForDeepDiagnostics(t *testing.T) {
	parsed, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	capture := &fakeCapture{}
	engine := Engine{Capture: capture}

	result := engine.Run(context.Background(), Config{URL: parsed, Deep: true})

	if !capture.started {
		t.Fatal("expected capture to start")
	}
	if result.CapturePath != "trace.pcap" {
		t.Fatalf("unexpected capture path: %q", result.CapturePath)
	}
}
