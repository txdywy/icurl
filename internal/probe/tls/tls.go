package tlsprobe

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type Probe struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	started := time.Now()
	address := net.JoinHostPort(target.Host, target.Port)
	result := evidence.ProbeResult{
		ProbeName:  "TLS",
		Layer:      evidence.LayerTLS,
		Target:     address,
		StartedAt:  &started,
		Confidence: evidence.ConfidenceObserved,
	}

	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		finish(&result, evidence.ResultFailed, evidence.ErrorUnknown, err.Error())
		return result
	}
	defer conn.Close()

	result.RemoteAddress = conn.RemoteAddr().String()
	result.LocalAddress = conn.LocalAddr().String()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         target.Host,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: p.InsecureSkipVerify,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		result.Observations = []string{"TLS handshake did not complete"}
		finish(&result, evidence.ResultFailed, evidence.ErrorReset, err.Error())
		return result
	}

	state := tlsConn.ConnectionState()
	result.Observations = []string{"TLS handshake succeeded", "ALPN " + state.NegotiatedProtocol}
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
