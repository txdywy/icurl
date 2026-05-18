package request

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRunnerExecutesHTTP11Request(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %q", r.Method)
		}
		if got := r.Header.Get("X-Test"); got != "yes" {
			t.Fatalf("expected X-Test header, got %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if string(body) != "payload" {
			t.Fatalf("expected request body payload, got %q", string(body))
		}
		w.Header().Set("X-Response", "present")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	runner := NewRunner()
	result, err := runner.Do(context.Background(), Config{
		URL:            server.URL,
		Headers:        http.Header{"X-Test": []string{"yes"}},
		Body:           "payload",
		IncludeHeaders: true,
		Protocol:       ProtocolHTTP11,
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}

	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", result.StatusCode)
	}
	if result.Protocol != "HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1, got %q", result.Protocol)
	}
	if string(result.Body) != "hello" {
		t.Fatalf("expected body hello, got %q", string(result.Body))
	}
	if got := result.ResponseHeaders.Get("X-Response"); got != "present" {
		t.Fatalf("expected response header, got %q", got)
	}
}

func TestRunnerUsesHTTP3TransportWhenForced(t *testing.T) {
	runner := NewRunner()
	runner.newHTTP3RoundTripper = func(Config) (http.RoundTripper, func() error, error) {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Proto:      "HTTP/3.0",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("h3")),
				Request:    req,
			}, nil
		}), func() error { return nil }, nil
	}

	result, err := runner.Do(context.Background(), Config{
		URL:      "https://example.test/",
		Protocol: ProtocolHTTP3Only,
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}

	if result.Protocol != "HTTP/3.0" {
		t.Fatalf("expected HTTP/3.0, got %q", result.Protocol)
	}
	if string(result.Body) != "h3" {
		t.Fatalf("expected body h3, got %q", string(result.Body))
	}
}

func TestRunnerHTTP3FallbackReusesMaxTimeDeadline(t *testing.T) {
	fallbackHit := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHit <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()

	runner := NewRunner()
	runner.newHTTP3RoundTripper = func(Config) (http.RoundTripper, func() error, error) {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}), func() error { return nil }, nil
	}

	started := time.Now()
	_, err := runner.Do(context.Background(), Config{
		URL:      server.URL,
		Protocol: ProtocolHTTP3,
		MaxTime:  20 * time.Millisecond,
	})
	duration := time.Since(started)
	if err == nil {
		t.Fatal("expected Do to return an error")
	}
	if duration >= 150*time.Millisecond {
		t.Fatalf("expected fallback to reuse expired deadline, took %v", duration)
	}
	select {
	case <-fallbackHit:
		t.Fatal("expected fallback to reuse expired context before sending request")
	default:
	}
}

func TestRunnerFollowsRedirectWhenEnabled(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("final"))
	}))
	defer final.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redirect.Close()

	runner := NewRunner()
	result, err := runner.Do(context.Background(), Config{
		URL:            redirect.URL,
		FollowRedirect: true,
		Protocol:       ProtocolHTTP11,
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}

	if string(result.Body) != "final" {
		t.Fatalf("expected body final, got %q", string(result.Body))
	}
	if len(result.Redirects) != 1 {
		t.Fatalf("expected one redirect, got %d", len(result.Redirects))
	}
	if result.Redirects[0].StatusCode != http.StatusFound {
		t.Fatalf("expected redirect status 302, got %d", result.Redirects[0].StatusCode)
	}
	if result.Redirects[0].From == "" {
		t.Fatal("expected redirect From to be populated")
	}
	if result.Redirects[0].To == "" {
		t.Fatal("expected redirect To to be populated")
	}
}
