package quicprobe

import (
	"context"
	"errors"
	"net"
	"strings"
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

	var response request.Result
	var err error

	ips := target.IPs
	if len(ips) == 0 {
		response, err = p.Runner.Do(ctx, request.Config{
			URL:            target.URL.String(),
			Host:           target.Host, // Pass explicit host for SNI
			Protocol:       request.ProtocolHTTP3Only,
			MaxTime:        10 * time.Second,
			ConnectTimeout: 5 * time.Second,
		})
	} else {
		for _, ip := range ips {
			u := *target.URL
			u.Host = net.JoinHostPort(ip.String(), target.Port)
			response, err = p.Runner.Do(ctx, request.Config{
				URL:            u.String(),
				Host:           target.Host, // Pass explicit host for SNI
				Protocol:       request.ProtocolHTTP3Only,
				MaxTime:        10 * time.Second,
				ConnectTimeout: 5 * time.Second,
			})
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		result.Observations = []string{"HTTP/3 over QUIC did not complete"}
		kind := evidence.ErrorUnknown
		res := evidence.ResultFailed
		errStr := err.Error()
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
			kind = evidence.ErrorTimeout
			res = evidence.ResultTimeout
		} else if strings.Contains(errStr, "refused") {
			kind = evidence.ErrorRefused
		} else if strings.Contains(errStr, "reset") {
			kind = evidence.ErrorReset
		} else if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
			kind = evidence.ErrorCertificate
		}
		finish(&result, res, kind, err.Error())
		return result
	}

	if response.Body != nil {
		defer func() {
			_ = response.Body.Close()
		}()
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
