package quicprobe

import (
	"context"
	"net"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
	"icurl/internal/request"
)

type Runner interface {
	Do(context.Context, request.Config) (request.Result, error)
}

type Probe struct {
	Runner Runner
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	started := time.Now()
	result := evidence.ProbeResult{
		ProbeName:  "QUICHTTP3",
		Layer:      evidence.LayerQUIC,
		Target:     target.URL.String(),
		StartedAt:  &started,
		Confidence: evidence.ConfidenceObserved,
	}

	if p.Runner == nil {
		finish(&result, evidence.ResultFailed, evidence.ErrorUnknown, "QUIC runner is nil")
		return result
	}

	urlStr := target.URL.String()
	if len(target.IPs) > 0 {
		// Replace hostname with IP to skip DNS resolution
		u := *target.URL
		u.Host = net.JoinHostPort(target.IPs[0].String(), target.Port)
		urlStr = u.String()
	}

	response, err := p.Runner.Do(ctx, request.Config{
		URL:            urlStr,
		Host:           target.Host, // Pass explicit host for SNI
		Protocol:       request.ProtocolHTTP3Only,
		MaxTime:        10 * time.Second,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		result.Observations = []string{"HTTP/3 over QUIC did not complete"}
		finish(&result, evidence.ResultTimeout, evidence.ErrorTimeout, err.Error())
		return result
	}

	result.Observations = []string{"HTTP/3 request succeeded over " + response.Protocol}
	finish(&result, evidence.ResultOK, evidence.ErrorNone, "")
	return result
}

func finish(result *evidence.ProbeResult, probeResult evidence.Result, kind evidence.ErrorKind, message string) {
	finished := time.Now()
	result.FinishedAt = &finished
	result.DurationNS = finished.Sub(*result.StartedAt).Nanoseconds()
	result.Result = probeResult
	result.ErrorKind = kind
	result.ErrorMessage = message
}
