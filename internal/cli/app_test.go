package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"icurl/internal/diagnose"
	"icurl/internal/evidence"
	"icurl/internal/request"
)

func TestRunShowsUsageWithoutArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(context.Background(), []string{}, &stdout, &stderr, Dependencies{})

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage: icurl") {
		t.Fatalf("expected usage in stderr, got %q", stderr.String())
	}
}

type recordingRequester struct {
	cfg request.Config
}

func (r *recordingRequester) Do(ctx context.Context, cfg request.Config) (request.Result, error) {
	_ = ctx
	r.cfg = cfg
	return request.Result{StatusCode: 200, Protocol: "HTTP/1.1"}, nil
}

type recordingDiagnoser struct {
	cfg diagnose.Config
}

func (d *recordingDiagnoser) Run(ctx context.Context, cfg diagnose.Config) diagnose.Result {
	_ = ctx
	d.cfg = cfg
	return diagnose.Result{
		Target: cfg.URL.String(),
		Assessment: evidence.Assessment{
			Level:    evidence.AssessmentSuspiciousHigh,
			Category: "TLS_SNI_INTERRUPTION_PATTERN",
		},
	}
}

func TestRunRoutesDiagnoseCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"diagnose", "--deep", "https://example.com"}, &stdout, &stderr, Dependencies{Diagnoser: diag})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}
	if diag.cfg.URL == nil || diag.cfg.URL.String() != "https://example.com" {
		t.Fatalf("unexpected diagnose URL: %#v", diag.cfg.URL)
	}
	if !diag.cfg.Deep {
		t.Fatalf("expected deep diagnostics")
	}
	if !strings.Contains(stdout.String(), "Assessment: SUSPICIOUS_HIGH TLS_SNI_INTERRUPTION_PATTERN") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestRunParsesRequestFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	req := &recordingRequester{}

	code := Run(context.Background(), []string{
		"-X", "POST",
		"-H", "Content-Type: application/json",
		"-d", "{}",
		"-i",
		"-L",
		"--connect-timeout", "2s",
		"--max-time", "5s",
		"--http2",
		"https://example.com",
	}, &stdout, &stderr, Dependencies{Requester: req})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}
	if req.cfg.URL != "https://example.com" {
		t.Fatalf("unexpected URL %q", req.cfg.URL)
	}
	if req.cfg.EffectiveMethod() != "POST" {
		t.Fatalf("unexpected method %q", req.cfg.EffectiveMethod())
	}
	if got := req.cfg.Headers.Get("Content-Type"); got != "application/json" {
		t.Fatalf("unexpected content type %q", got)
	}
	if req.cfg.Protocol != request.ProtocolHTTP2 {
		t.Fatalf("unexpected protocol %q", req.cfg.Protocol)
	}
}
