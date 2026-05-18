package request

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
}
