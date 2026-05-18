package tlsprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

func TestRunNegotiatesWithLocalTLSServer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	addr := server.Listener.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}

	result := Probe{InsecureSkipVerify: true}.Run(context.Background(), probe.Target{Host: "127.0.0.1", Port: port})

	if result.Result != evidence.ResultOK {
		t.Fatalf("unexpected result: want %s got %s: %s", evidence.ResultOK, result.Result, result.ErrorMessage)
	}
	if result.ErrorKind != evidence.ErrorNone {
		t.Fatalf("unexpected error kind: want %s got %s", evidence.ErrorNone, result.ErrorKind)
	}
	if result.ProbeName != "TLS" || result.Layer != evidence.LayerTLS || result.Target != net.JoinHostPort("127.0.0.1", port) {
		t.Fatalf("unexpected base fields: %#v", result)
	}
	if result.RemoteAddress == "" || result.LocalAddress == "" {
		t.Fatalf("addresses not populated: %#v", result)
	}
	assertObservation(t, result.Observations, "TLS handshake succeeded")
	assertObservation(t, result.Observations, "ALPN h2")
	if result.StartedAt == nil || result.FinishedAt == nil || result.DurationNS < 0 || result.Confidence != evidence.ConfidenceObserved {
		t.Fatalf("timing/confidence fields not populated: %#v", result)
	}
}

func TestRunReportsCertificateError(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	addr := server.Listener.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}

	result := Probe{InsecureSkipVerify: false}.Run(context.Background(), probe.Target{Host: "127.0.0.1", Port: port})

	if result.Result != evidence.ResultFailed {
		t.Fatalf("unexpected result: want %s got %s", evidence.ResultFailed, result.Result)
	}
	if result.ErrorKind != evidence.ErrorCertificate {
		t.Fatalf("unexpected error kind: want %s got %s: %s", evidence.ErrorCertificate, result.ErrorKind, result.ErrorMessage)
	}
}

func assertObservation(t *testing.T, observations []string, want string) {
	t.Helper()
	for _, observation := range observations {
		if observation == want {
			return
		}
	}
	t.Fatalf("missing observation %q in %#v", want, observations)
}
