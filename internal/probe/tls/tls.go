package tlsprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
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
		res := evidence.ResultFailed
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			kind = evidence.ErrorTimeout
			res = evidence.ResultTimeout
		}
		finish(&result, res, kind, err.Error())
		return result
	}
	defer func() {
		_ = conn.Close()
	}()

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
		kind := evidence.ErrorReset
		res := evidence.ResultFailed
		if _, ok := err.(*tls.CertificateVerificationError); ok {
			kind = evidence.ErrorCertificate
		} else {
			errStr := err.Error()
			if errors.Is(err, context.DeadlineExceeded) || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
				kind = evidence.ErrorTimeout
				res = evidence.ResultTimeout
			} else if len(errStr) > 4 && errStr[:4] == "tls:" {
				if len(errStr) > 33 && errStr[:33] == "tls: failed to verify certificate" {
					kind = evidence.ErrorCertificate
				}
			}
		}
		finish(&result, res, kind, err.Error())
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
