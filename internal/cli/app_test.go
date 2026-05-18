package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	err error
}

func (r *recordingRequester) Do(ctx context.Context, cfg request.Config) (request.Result, error) {
	_ = ctx
	r.cfg = cfg
	if r.err != nil {
		return request.Result{}, r.err
	}
	return request.Result{StatusCode: 200, Protocol: "HTTP/1.1"}, nil
}

type recordingDiagnoser struct {
	cfg    diagnose.Config
	called bool
}

func (d *recordingDiagnoser) Run(ctx context.Context, cfg diagnose.Config) diagnose.Result {
	_ = ctx
	d.cfg = cfg
	d.called = true
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

func TestRunRequestDiagnoseOnFailureCallsDiagnoser(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	requestErr := errors.New("request failed")
	req := &recordingRequester{err: requestErr}
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"--diagnose", "https://example.com"}, &stdout, &stderr, Dependencies{Requester: req, Diagnoser: diag})

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !diag.called {
		t.Fatalf("diagnoser should be called")
	}
	if diag.cfg.URL == nil || diag.cfg.URL.String() != "https://example.com" {
		t.Fatalf("unexpected diagnose URL: %#v", diag.cfg.URL)
	}
	if diag.cfg.Deep {
		t.Fatalf("request diagnostics should not run deep diagnostics")
	}
	if !strings.Contains(stderr.String(), "icurl: request failed") {
		t.Fatalf("expected request error in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "TLS_SNI_INTERRUPTION_PATTERN") {
		t.Fatalf("expected diagnostic category in stdout, got %q", stdout.String())
	}
}

func TestRunRequestFailureWithoutDiagnoseDoesNotCallDiagnoser(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	req := &recordingRequester{err: errors.New("request failed")}
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"https://example.com"}, &stdout, &stderr, Dependencies{Requester: req, Diagnoser: diag})

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if diag.called {
		t.Fatalf("diagnoser should not be called")
	}
	if !strings.Contains(stderr.String(), "icurl: request failed") {
		t.Fatalf("expected request error in stderr, got %q", stderr.String())
	}
	if stdout.String() != "" {
		t.Fatalf("expected empty stdout, got %q", stdout.String())
	}
}

func TestRunRequestDiagnoseJSONOnFailure(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	req := &recordingRequester{err: errors.New("request failed")}
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"--diagnose", "--json", "https://example.com"}, &stdout, &stderr, Dependencies{Requester: req, Diagnoser: diag})

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !diag.called {
		t.Fatalf("diagnoser should be called")
	}
	if !strings.Contains(stderr.String(), "icurl: request failed") {
		t.Fatalf("expected request error in stderr, got %q", stderr.String())
	}
	var result diagnose.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("expected diagnostic JSON, got error %v and output %q", err, stdout.String())
	}
	if result.Assessment.Category != "TLS_SNI_INTERRUPTION_PATTERN" {
		t.Fatalf("unexpected diagnostic category %q", result.Assessment.Category)
	}
}

func TestRunDiagnoseDeepEmitsWarning(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"diagnose", "--deep", "https://example.com"}, &stdout, &stderr, Dependencies{Diagnoser: diag})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}
	if !diag.called {
		t.Fatalf("diagnoser should be called")
	}
	if !strings.Contains(stderr.String(), "Deep diagnostics require sudo to run /usr/sbin/tcpdump.") {
		t.Fatalf("expected sudo warning in stderr, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Packet captures may contain sensitive data and are saved locally.") {
		t.Fatalf("expected privacy warning in stderr, got %q", stderr.String())
	}
}

func TestRunDiagnoseWithoutDeepDoesNotEmitWarning(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"diagnose", "https://example.com"}, &stdout, &stderr, Dependencies{Diagnoser: diag})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}
	if !diag.called {
		t.Fatalf("diagnoser should be called")
	}
	if strings.Contains(stderr.String(), "Deep diagnostics require sudo") || strings.Contains(stderr.String(), "Packet captures may contain sensitive data") {
		t.Fatalf("expected no deep warning, got %q", stderr.String())
	}
}

func TestRunDiagnoseRejectsHostlessURL(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"diagnose", "example.com"}, &stdout, &stderr, Dependencies{Diagnoser: diag})

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if diag.called {
		t.Fatalf("diagnoser should not be called")
	}
	if !strings.Contains(stderr.String(), "icurl: invalid URL: expected http or https URL with host") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestRunDiagnoseRejectsRelativePath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	diag := &recordingDiagnoser{}

	code := Run(context.Background(), []string{"diagnose", "/path"}, &stdout, &stderr, Dependencies{Diagnoser: diag})

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if diag.called {
		t.Fatalf("diagnoser should not be called")
	}
	if !strings.Contains(stderr.String(), "icurl: invalid URL: expected http or https URL with host") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
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
