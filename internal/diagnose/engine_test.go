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
	if len(tcpProbe.target.IPs) != 0 {
		t.Fatalf("expected empty IPs, got %#v", tcpProbe.target.IPs)
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
