package tcp

import (
	"context"
	"net"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type Probe struct {
	Timeout time.Duration
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	started := time.Now()
	address := net.JoinHostPort(target.Host, target.Port)
	result := evidence.ProbeResult{
		ProbeName:  "TCP",
		Layer:      evidence.LayerTCP,
		Target:     address,
		StartedAt:  &started,
		Confidence: evidence.ConfidenceObserved,
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	
	var conn net.Conn
	var err error
	if len(target.IPs) > 0 {
		for _, ip := range target.IPs {
			addr := net.JoinHostPort(ip.String(), target.Port)
			conn, err = dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				break
			}
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}

	if err != nil {
		kind := evidence.ErrorUnknown
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			kind = evidence.ErrorTimeout
		}
		finish(&result, evidence.ResultFailed, kind, err.Error())
		return result
	}
	defer func() {
		_ = conn.Close()
	}()

	result.RemoteAddress = conn.RemoteAddr().String()
	result.LocalAddress = conn.LocalAddr().String()
	result.Observations = []string{"TCP connect succeeded"}
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
