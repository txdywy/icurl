package tcp

import (
	"context"
	"net"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

func TestRunConnectsToLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}

	result := Probe{}.Run(context.Background(), probe.Target{Host: "127.0.0.1", Port: port})
	<-accepted

	if result.Result != evidence.ResultOK {
		t.Fatalf("unexpected result: want %s got %s", evidence.ResultOK, result.Result)
	}
	if result.ErrorKind != evidence.ErrorNone {
		t.Fatalf("unexpected error kind: want %s got %s", evidence.ErrorNone, result.ErrorKind)
	}
	if result.ProbeName != "TCP" || result.Layer != evidence.LayerTCP || result.Target != net.JoinHostPort("127.0.0.1", port) {
		t.Fatalf("unexpected base fields: %#v", result)
	}
	if result.RemoteAddress == "" || result.LocalAddress == "" {
		t.Fatalf("addresses not populated: %#v", result)
	}
	if len(result.Observations) != 1 || result.Observations[0] != "TCP connect succeeded" {
		t.Fatalf("unexpected observations: %#v", result.Observations)
	}
	if result.StartedAt == nil || result.FinishedAt == nil || result.DurationNS < 0 || result.Confidence != evidence.ConfidenceObserved {
		t.Fatalf("timing/confidence fields not populated: %#v", result)
	}
}
