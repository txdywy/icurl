package dns

import (
	"context"
	"net"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type Probe struct {
	Resolver Resolver
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	started := time.Now()
	result := evidence.ProbeResult{
		ProbeName:  "DNS",
		Layer:      evidence.LayerDNS,
		Target:     target.Host,
		StartedAt:  &started,
		Confidence: evidence.ConfidenceObserved,
	}

	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIP(ctx, "ip", target.Host)
	if err != nil {
		finish(&result, evidence.ResultFailed, evidence.ErrorUnknown, err.Error())
		return result
	}
	if len(ips) == 0 {
		finish(&result, evidence.ResultFailed, evidence.ErrorUnknown, "resolver returned no addresses")
		return result
	}

	for _, ip := range ips {
		result.Observations = append(result.Observations, "resolved "+ip.String())
		if isSuspicious(ip) {
			finish(&result, evidence.ResultFailed, evidence.ErrorSuspiciousDNS, "resolver returned suspicious address "+ip.String())
			return result
		}
	}

	finish(&result, evidence.ResultOK, evidence.ErrorNone, "")
	return result
}

func isSuspicious(ip net.IP) bool {
	parsed := net.ParseIP(ip.String())
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsMulticast() || parsed.IsUnspecified() {
		return true
	}
	return inCIDR(parsed, "192.0.2.0/24") || inCIDR(parsed, "198.51.100.0/24") || inCIDR(parsed, "203.0.113.0/24")
}

func inCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func finish(result *evidence.ProbeResult, probeResult evidence.Result, kind evidence.ErrorKind, message string) {
	finished := time.Now()
	result.FinishedAt = &finished
	result.DurationNS = finished.Sub(*result.StartedAt).Nanoseconds()
	result.Result = probeResult
	result.ErrorKind = kind
	result.ErrorMessage = message
}
