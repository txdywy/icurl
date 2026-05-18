package quicprobe

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
	"icurl/internal/request"
)

type fakeRunner struct {
	result request.Result
	err    error
	config request.Config
	called bool
}

func (r *fakeRunner) Do(ctx context.Context, cfg request.Config) (request.Result, error) {
	r.config = cfg
	r.called = true
	return r.result, r.err
}

func TestRunSucceedsOnHTTP3Result(t *testing.T) {
	targetURL := mustParseURL(t, "https://example.com/")
	runner := &fakeRunner{result: request.Result{StatusCode: 200, Protocol: "HTTP/3.0"}}

	result := Probe{Runner: runner}.Run(context.Background(), probe.Target{URL: targetURL})

	if !runner.called {
		t.Fatal("runner was not called")
	}
	if runner.config.URL != targetURL.String() || runner.config.Protocol != request.ProtocolHTTP3Only {
		t.Fatalf("unexpected request config: %#v", runner.config)
	}
	if runner.config.MaxTime != 10*time.Second || runner.config.ConnectTimeout != 5*time.Second {
		t.Fatalf("unexpected timeouts: %#v", runner.config)
	}
	if result.Result != evidence.ResultOK || result.ErrorKind != evidence.ErrorNone || result.ErrorMessage != "" {
		t.Fatalf("unexpected success result: %#v", result)
	}
	assertQUICBaseFields(t, result, targetURL.String())
	assertObservation(t, result.Observations, "HTTP/3 request succeeded over HTTP/3.0")
}

func TestRunTimesOutOnRunnerError(t *testing.T) {
	targetURL := mustParseURL(t, "https://example.com/")
	runner := &fakeRunner{err: errors.New("deadline exceeded")}

	result := Probe{Runner: runner}.Run(context.Background(), probe.Target{URL: targetURL})

	if result.Result != evidence.ResultTimeout || result.ErrorKind != evidence.ErrorTimeout || result.ErrorMessage != "deadline exceeded" {
		t.Fatalf("unexpected error result: %#v", result)
	}
	assertQUICBaseFields(t, result, targetURL.String())
	assertObservation(t, result.Observations, "HTTP/3 over QUIC did not complete")
}

func TestRunFailsWhenRunnerIsNil(t *testing.T) {
	targetURL := mustParseURL(t, "https://example.com/")

	result := Probe{}.Run(context.Background(), probe.Target{URL: targetURL})

	if result.Result != evidence.ResultFailed || result.ErrorKind != evidence.ErrorUnknown || result.ErrorMessage != "QUIC runner is nil" {
		t.Fatalf("unexpected nil runner result: %#v", result)
	}
	assertQUICBaseFields(t, result, targetURL.String())
}

func assertQUICBaseFields(t *testing.T, result evidence.ProbeResult, target string) {
	t.Helper()
	if result.ProbeName != "QUICHTTP3" || result.Layer != evidence.LayerQUIC || result.Target != target {
		t.Fatalf("unexpected base fields: %#v", result)
	}
	if result.StartedAt == nil || result.FinishedAt == nil || result.DurationNS < 0 {
		t.Fatalf("timing fields not populated: %#v", result)
	}
	if result.Confidence != evidence.ConfidenceObserved {
		t.Fatalf("unexpected confidence: %s", result.Confidence)
	}
}

func assertObservation(t *testing.T, observations []string, want string) {
	t.Helper()
	if len(observations) != 1 || observations[0] != want {
		t.Fatalf("unexpected observations: %#v", observations)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return u
}
