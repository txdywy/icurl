package dns

import (
	"context"
	"net"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type fakeResolver struct {
	ips    []net.IP
	err    error
	called bool
}

func (r *fakeResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	r.called = true
	return r.ips, r.err
}

func TestRunAcceptsPublicAddress(t *testing.T) {
	resolver := &fakeResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}
	result := Probe{Resolver: resolver}.Run(context.Background(), probe.Target{Host: "example.com"})

	if result.Result != evidence.ResultOK {
		t.Fatalf("unexpected result: want %s got %s", evidence.ResultOK, result.Result)
	}
	if result.ErrorKind != evidence.ErrorNone {
		t.Fatalf("unexpected error kind: want %s got %s", evidence.ErrorNone, result.ErrorKind)
	}
	assertBaseFields(t, result)
	if len(result.Observations) != 1 || result.Observations[0] != "resolved 93.184.216.34" {
		t.Fatalf("unexpected observations: %#v", result.Observations)
	}
}

func TestRunFlagsDocumentationAddress(t *testing.T) {
	resolver := &fakeResolver{ips: []net.IP{net.ParseIP("203.0.113.10")}}
	result := Probe{Resolver: resolver}.Run(context.Background(), probe.Target{Host: "example.com"})

	if result.Result != evidence.ResultFailed {
		t.Fatalf("unexpected result: want %s got %s", evidence.ResultFailed, result.Result)
	}
	if result.ErrorKind != evidence.ErrorSuspiciousDNS {
		t.Fatalf("unexpected error kind: want %s got %s", evidence.ErrorSuspiciousDNS, result.ErrorKind)
	}
	assertBaseFields(t, result)
}

func TestRunUsesPreResolvedAddresses(t *testing.T) {
	resolver := &fakeResolver{ips: []net.IP{net.ParseIP("203.0.113.10")}}

	result := Probe{Resolver: resolver}.Run(context.Background(), probe.Target{Host: "example.com", IPs: []net.IP{net.ParseIP("93.184.216.34")}})

	if resolver.called {
		t.Fatal("expected pre-resolved target IPs to skip resolver lookup")
	}
	if result.Result != evidence.ResultOK {
		t.Fatalf("unexpected result: want %s got %s", evidence.ResultOK, result.Result)
	}
	if len(result.Observations) != 1 || result.Observations[0] != "resolved 93.184.216.34" {
		t.Fatalf("unexpected observations: %#v", result.Observations)
	}
}

func assertBaseFields(t *testing.T, result evidence.ProbeResult) {
	t.Helper()
	if result.ProbeName != "DNS" || result.Layer != evidence.LayerDNS || result.Target != "example.com" {
		t.Fatalf("unexpected base fields: %#v", result)
	}
	if result.StartedAt == nil || result.FinishedAt == nil || result.DurationNS < 0 {
		t.Fatalf("timing fields not populated: %#v", result)
	}
	if result.Confidence != evidence.ConfidenceObserved {
		t.Fatalf("unexpected confidence: %s", result.Confidence)
	}
}
