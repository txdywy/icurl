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

var documentationNetworks = mustParseCIDRs(
	"192.0.2.0/24",
	"198.51.100.0/24",
	"203.0.113.0/24",
)

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	started := time.Now()
	result := evidence.ProbeResult{
		ProbeName:  "DNS",
		Layer:      evidence.LayerDNS,
		Target:     target.Host,
		StartedAt:  &started,
		Confidence: evidence.ConfidenceObserved,
	}

	ips := target.IPs
	if len(ips) == 0 {
		resolver := p.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}

		resolved, err := resolver.LookupIP(ctx, "ip", target.Host)
		if err != nil {
			finish(&result, evidence.ResultFailed, evidence.ErrorUnknown, err.Error())
			return result
		}
		ips = resolved
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
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range documentationNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}

func finish(result *evidence.ProbeResult, probeResult evidence.Result, kind evidence.ErrorKind, message string) {
	finished := time.Now()
	result.FinishedAt = &finished
	result.DurationNS = finished.Sub(*result.StartedAt).Nanoseconds()
	result.Result = probeResult
	result.ErrorKind = kind
	result.ErrorMessage = message
}
