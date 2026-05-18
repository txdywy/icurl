# icurl Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first usable `icurl` CLI: common curl-like HTTP requests, HTTP/1.1, HTTP/2, HTTP/3, layered diagnostics, evidence classification, human/JSON reports, and macOS optional deep packet capture.

**Architecture:** Use a small standard-library CLI layer that converts arguments into request and diagnostic configs. Keep request execution, probes, evidence, classification, reporting, and macOS packet capture in separate `internal` packages with testable interfaces. Implement HTTP/1.1 and HTTP/2 with Go `net/http`; implement HTTP/3 with `github.com/quic-go/quic-go/http3`.

**Tech Stack:** Go 1.23 or newer, standard library `flag`, `net/http`, `httptrace`, `crypto/tls`, `net`, `encoding/json`, `os/exec`, plus `github.com/quic-go/quic-go/http3` for HTTP/3.

---

## Scope Check

The design covers several subsystems, but they form one vertical CLI product. This plan keeps each task independently testable and commit-sized while producing one integrated MVP.

## File Structure

Create these files and keep responsibilities focused:

```text
go.mod                                  module and dependency declarations
README.md                               user-facing quickstart and scope statement
cmd/icurl/main.go                       executable entry point only
internal/cli/app.go                     command routing, flag parsing, and dependency injection
internal/cli/app_test.go                CLI parsing and routing tests
internal/request/config.go              request config types and header parsing helpers
internal/request/config_test.go         request config tests
internal/request/runner.go              HTTP/1.1, HTTP/2, and HTTP/3 request runner
internal/request/runner_test.go         request runner tests with local servers and fake transports
internal/request/result.go              request result, timing, and protocol metadata
internal/evidence/evidence.go           shared evidence, probe result, and assessment types
internal/evidence/evidence_test.go      evidence constructor and JSON stability tests
internal/report/human.go                human-readable request and diagnostic reports
internal/report/json.go                 JSON report rendering
internal/report/report_test.go          report rendering tests
internal/probe/probe.go                 probe interfaces and shared target type
internal/probe/dns/dns.go               DNS resolver probe
internal/probe/dns/dns_test.go          DNS probe tests with fake resolvers
internal/probe/tcp/tcp.go               TCP connect probe
internal/probe/tcp/tcp_test.go          TCP probe tests with local listeners
internal/probe/tls/tls.go               TLS and ALPN probe
internal/probe/tls/tls_test.go          TLS probe tests with local TLS servers
internal/probe/http/http.go             HTTP/1.1 and HTTP/2 probe wrapper around request runner
internal/probe/http/http_test.go        HTTP probe tests with fake request runner
internal/probe/quic/quic.go             UDP and HTTP/3 probe wrapper
internal/probe/quic/quic_test.go        QUIC probe tests with fake HTTP/3 runner
internal/classifier/classifier.go       evidence-to-assessment rules
internal/classifier/classifier_test.go  classification rule tests
internal/diagnose/engine.go             diagnostic orchestration
internal/diagnose/engine_test.go        orchestration tests with fake probes
internal/platform/macos/capture.go      macOS tcpdump packet capture orchestration
internal/platform/macos/capture_test.go packet capture command construction tests
```

## Task 1: Initialize Go Module and CLI Entry Point

**Files:**
- Create: `go.mod`
- Create: `cmd/icurl/main.go`
- Create: `internal/cli/app.go`
- Create: `internal/cli/app_test.go`

- [ ] **Step 1: Create module file**

Create `go.mod`:

```go
module icurl

go 1.23
```

- [ ] **Step 2: Write the failing CLI smoke test**

Create `internal/cli/app_test.go`:

```go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunShowsUsageWithoutArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(context.Background(), []string{}, &stdout, &stderr, Dependencies{})

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage: icurl") {
		t.Fatalf("expected usage in stderr, got %q", stderr.String())
	}
}
```

- [ ] **Step 3: Run the test and verify it fails**

Run:

```bash
go test ./internal/cli -run TestRunShowsUsageWithoutArguments -v
```

Expected: FAIL because package `internal/cli` has no implementation.

- [ ] **Step 4: Add minimal CLI implementation**

Create `internal/cli/app.go`:

```go
package cli

import (
	"context"
	"fmt"
	"io"
)

type Dependencies struct{}

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps Dependencies) int {
	_ = ctx
	_ = stdout
	_ = deps

	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: icurl [options] URL")
		fmt.Fprintln(stderr, "       icurl diagnose [options] URL")
		return 2
	}

	fmt.Fprintln(stderr, "icurl: request execution is not wired yet")
	return 2
}
```

Create `cmd/icurl/main.go`:

```go
package main

import (
	"context"
	"os"

	"icurl/internal/cli"
)

func main() {
	code := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{})
	os.Exit(code)
}
```

- [ ] **Step 5: Run tests and build**

Run:

```bash
go test ./...
go build ./cmd/icurl
```

Expected: both commands PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod cmd/icurl/main.go internal/cli/app.go internal/cli/app_test.go
git commit -m "Initialize icurl Go CLI"
```

## Task 2: Add Request Configuration and CLI Flag Parsing

**Files:**
- Create: `internal/request/config.go`
- Create: `internal/request/config_test.go`
- Modify: `internal/cli/app.go`
- Modify: `internal/cli/app_test.go`

- [ ] **Step 1: Write request config tests**

Create `internal/request/config_test.go`:

```go
package request

import "testing"

func TestHeaderListSetParsesNameAndValue(t *testing.T) {
	var headers HeaderList
	if err := headers.Set("Accept: application/json"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if got := headers.Values.Get("Accept"); got != "application/json" {
		t.Fatalf("expected Accept header, got %q", got)
	}
}

func TestHeaderListSetRejectsMissingColon(t *testing.T) {
	var headers HeaderList
	if err := headers.Set("Accept application/json"); err == nil {
		t.Fatal("expected error for header without colon")
	}
}

func TestConfigMethodDefaultsToHeadWhenHeadIsTrue(t *testing.T) {
	cfg := Config{Head: true}
	if got := cfg.EffectiveMethod(); got != "HEAD" {
		t.Fatalf("expected HEAD, got %q", got)
	}
}

func TestConfigMethodDefaultsToPostWhenBodyExists(t *testing.T) {
	cfg := Config{Body: "hello"}
	if got := cfg.EffectiveMethod(); got != "POST" {
		t.Fatalf("expected POST, got %q", got)
	}
}

func TestConfigMethodDefaultsToGet(t *testing.T) {
	cfg := Config{}
	if got := cfg.EffectiveMethod(); got != "GET" {
		t.Fatalf("expected GET, got %q", got)
	}
}
```

- [ ] **Step 2: Run request tests and verify failure**

Run:

```bash
go test ./internal/request -v
```

Expected: FAIL because package `internal/request` has no implementation.

- [ ] **Step 3: Implement request config types**

Create `internal/request/config.go`:

```go
package request

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ProtocolMode string

const (
	ProtocolAuto      ProtocolMode = "auto"
	ProtocolHTTP11    ProtocolMode = "http1.1"
	ProtocolHTTP2     ProtocolMode = "http2"
	ProtocolHTTP3     ProtocolMode = "http3"
	ProtocolHTTP3Only ProtocolMode = "http3-only"
)

type Config struct {
	URL            string
	Method         string
	Headers        http.Header
	Body           string
	Head           bool
	IncludeHeaders bool
	FollowRedirect bool
	ConnectTimeout time.Duration
	MaxTime        time.Duration
	Protocol       ProtocolMode
	Diagnose       bool
	JSON           bool
}

func (c Config) EffectiveMethod() string {
	if c.Method != "" {
		return strings.ToUpper(c.Method)
	}
	if c.Head {
		return http.MethodHead
	}
	if c.Body != "" {
		return http.MethodPost
	}
	return http.MethodGet
}

type HeaderList struct {
	Values http.Header
}

func (h *HeaderList) String() string {
	return h.Values.Encode()
}

func (h *HeaderList) Set(value string) error {
	name, raw, ok := strings.Cut(value, ":")
	if !ok {
		return fmt.Errorf("header must be in Name: value form")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}
	if h.Values == nil {
		h.Values = make(http.Header)
	}
	h.Values.Add(name, strings.TrimSpace(raw))
	return nil
}
```

- [ ] **Step 4: Run request tests**

Run:

```bash
go test ./internal/request -v
```

Expected: PASS.

- [ ] **Step 5: Write CLI parsing tests**

Append to `internal/cli/app_test.go`:

```go
type recordingRequester struct {
	cfg request.Config
}

func (r *recordingRequester) Do(ctx context.Context, cfg request.Config) (request.Result, error) {
	_ = ctx
	r.cfg = cfg
	return request.Result{StatusCode: 200, Protocol: "HTTP/1.1"}, nil
}

func TestRunParsesRequestFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	req := &recordingRequester{}

	code := Run(context.Background(), []string{
		"-X", "POST",
		"-H", "Content-Type: application/json",
		"-d", "{}",
		"-i",
		"-L",
		"--connect-timeout", "2s",
		"--max-time", "5s",
		"--http2",
		"https://example.com",
	}, &stdout, &stderr, Dependencies{Requester: req})

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", code, stderr.String())
	}
	if req.cfg.URL != "https://example.com" {
		t.Fatalf("unexpected URL %q", req.cfg.URL)
	}
	if req.cfg.EffectiveMethod() != "POST" {
		t.Fatalf("unexpected method %q", req.cfg.EffectiveMethod())
	}
	if got := req.cfg.Headers.Get("Content-Type"); got != "application/json" {
		t.Fatalf("unexpected content type %q", got)
	}
	if req.cfg.Protocol != request.ProtocolHTTP2 {
		t.Fatalf("unexpected protocol %q", req.cfg.Protocol)
	}
}
```

Also add this import to `internal/cli/app_test.go`:

```go
"icurl/internal/request"
```

- [ ] **Step 6: Run CLI tests and verify failure**

Run:

```bash
go test ./internal/cli -run TestRunParsesRequestFlags -v
```

Expected: FAIL because `Dependencies.Requester` and request routing are not implemented.

- [ ] **Step 7: Implement CLI flag parsing**

Replace `internal/cli/app.go` with:

```go
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"icurl/internal/request"
)

type Requester interface {
	Do(context.Context, request.Config) (request.Result, error)
}

type Dependencies struct {
	Requester Requester
}

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps Dependencies) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	if args[0] == "diagnose" {
		fmt.Fprintln(stderr, "icurl: diagnose is not wired yet")
		return 2
	}

	cfg, err := parseRequestArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "icurl: %v\n", err)
		return 2
	}
	if deps.Requester == nil {
		fmt.Fprintln(stderr, "icurl: requester dependency is not configured")
		return 2
	}

	result, err := deps.Requester.Do(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "icurl: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "HTTP %d %s\n", result.StatusCode, result.Protocol)
	return 0
}

func parseRequestArgs(args []string, stderr io.Writer) (request.Config, error) {
	fs := flag.NewFlagSet("icurl", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var headers request.HeaderList
	cfg := request.Config{Headers: make(http.Header), Protocol: request.ProtocolAuto}
	var connectTimeout string
	var maxTime string
	var http11 bool
	var http2 bool
	var http3 bool
	var http3Only bool

	fs.StringVar(&cfg.Method, "X", "", "request method")
	fs.StringVar(&cfg.Method, "request", "", "request method")
	fs.Var(&headers, "H", "request header")
	fs.Var(&headers, "header", "request header")
	fs.StringVar(&cfg.Body, "d", "", "request body")
	fs.StringVar(&cfg.Body, "data", "", "request body")
	fs.BoolVar(&cfg.Head, "I", false, "send HEAD request")
	fs.BoolVar(&cfg.Head, "head", false, "send HEAD request")
	fs.BoolVar(&cfg.IncludeHeaders, "i", false, "include response headers")
	fs.BoolVar(&cfg.IncludeHeaders, "include", false, "include response headers")
	fs.BoolVar(&cfg.FollowRedirect, "L", false, "follow redirects")
	fs.BoolVar(&cfg.FollowRedirect, "location", false, "follow redirects")
	fs.StringVar(&connectTimeout, "connect-timeout", "10s", "connect timeout")
	fs.StringVar(&maxTime, "max-time", "30s", "total timeout")
	fs.BoolVar(&http11, "http1.1", false, "force HTTP/1.1")
	fs.BoolVar(&http2, "http2", false, "force HTTP/2")
	fs.BoolVar(&http3, "http3", false, "prefer HTTP/3")
	fs.BoolVar(&http3Only, "http3-only", false, "force HTTP/3 only")
	fs.BoolVar(&cfg.Diagnose, "diagnose", false, "run diagnostics after request failure")
	fs.BoolVar(&cfg.JSON, "json", false, "write JSON output")

	if err := fs.Parse(args); err != nil {
		return request.Config{}, err
	}
	if fs.NArg() != 1 {
		return request.Config{}, fmt.Errorf("expected exactly one URL")
	}

	cfg.URL = fs.Arg(0)
	cfg.Headers = headers.Values
	if cfg.Headers == nil {
		cfg.Headers = make(http.Header)
	}

	parsedConnectTimeout, err := time.ParseDuration(connectTimeout)
	if err != nil {
		return request.Config{}, fmt.Errorf("invalid --connect-timeout: %w", err)
	}
	parsedMaxTime, err := time.ParseDuration(maxTime)
	if err != nil {
		return request.Config{}, fmt.Errorf("invalid --max-time: %w", err)
	}
	cfg.ConnectTimeout = parsedConnectTimeout
	cfg.MaxTime = parsedMaxTime

	selected := 0
	for _, enabled := range []bool{http11, http2, http3, http3Only} {
		if enabled {
			selected++
		}
	}
	if selected > 1 {
		return request.Config{}, fmt.Errorf("choose only one HTTP protocol flag")
	}
	if http11 {
		cfg.Protocol = request.ProtocolHTTP11
	}
	if http2 {
		cfg.Protocol = request.ProtocolHTTP2
	}
	if http3 {
		cfg.Protocol = request.ProtocolHTTP3
	}
	if http3Only {
		cfg.Protocol = request.ProtocolHTTP3Only
	}

	return cfg, nil
}

func printUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: icurl [options] URL")
	fmt.Fprintln(stderr, "       icurl diagnose [options] URL")
}
```

- [ ] **Step 8: Run tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/request/config.go internal/request/config_test.go internal/cli/app.go internal/cli/app_test.go
git commit -m "Add curl-like request flag parsing"
```

## Task 3: Add Request Result Types and HTTP/1.1/HTTP/2 Runner

**Files:**
- Create: `internal/request/result.go`
- Create: `internal/request/runner.go`
- Create: `internal/request/runner_test.go`
- Modify: `cmd/icurl/main.go`

- [ ] **Step 1: Write HTTP runner tests**

Create `internal/request/runner_test.go`:

```go
package request

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunnerExecutesHTTP11Request(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("X-Test"); got != "yes" {
			t.Fatalf("expected header X-Test=yes, got %q", got)
		}
		w.Header().Set("X-Reply", "ok")
		fmt.Fprint(w, "hello")
	}))
	defer server.Close()

	runner := NewRunner()
	result, err := runner.Do(context.Background(), Config{
		URL:            server.URL,
		Method:         http.MethodPost,
		Headers:        http.Header{"X-Test": []string{"yes"}},
		Body:           "payload",
		IncludeHeaders: true,
		MaxTime:        5 * time.Second,
		ConnectTimeout: 5 * time.Second,
		Protocol:       ProtocolHTTP11,
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", result.StatusCode)
	}
	if result.Protocol != "HTTP/1.1" {
		t.Fatalf("expected HTTP/1.1, got %q", result.Protocol)
	}
	if strings.TrimSpace(string(result.Body)) != "hello" {
		t.Fatalf("unexpected body %q", string(result.Body))
	}
	if result.ResponseHeaders.Get("X-Reply") != "ok" {
		t.Fatalf("missing response header")
	}
}

func TestRunnerFollowsRedirectWhenEnabled(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "final")
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
		MaxTime:        5 * time.Second,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	if strings.TrimSpace(string(result.Body)) != "final" {
		t.Fatalf("unexpected body %q", string(result.Body))
	}
	if len(result.Redirects) != 1 {
		t.Fatalf("expected one redirect, got %d", len(result.Redirects))
	}
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./internal/request -run 'TestRunner' -v
```

Expected: FAIL because `NewRunner`, `Result`, and runner methods are missing.

- [ ] **Step 3: Implement request result types**

Create `internal/request/result.go`:

```go
package request

import (
	"net/http"
	"time"
)

type Timing struct {
	DNSStart          time.Time
	DNSDone           time.Time
	ConnectStart      time.Time
	ConnectDone       time.Time
	TLSHandshakeStart time.Time
	TLSHandshakeDone  time.Time
	FirstByte         time.Time
	Total             time.Duration
}

type Redirect struct {
	From       string
	To         string
	StatusCode int
}

type Result struct {
	URL             string
	StatusCode      int
	Protocol        string
	ResponseHeaders http.Header
	Body            []byte
	Timing          Timing
	Redirects       []Redirect
}
```

- [ ] **Step 4: Implement HTTP/1.1 and HTTP/2 runner**

Create `internal/request/runner.go`:

```go
package request

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"
)

type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Do(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Protocol == ProtocolHTTP3 || cfg.Protocol == ProtocolHTTP3Only {
		return Result{}, fmt.Errorf("HTTP/3 runner is not configured")
	}
	return r.doHTTP(ctx, cfg)
}

func (r *Runner) doHTTP(ctx context.Context, cfg Config) (Result, error) {
	if cfg.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.MaxTime)
		defer cancel()
	}

	var body io.Reader
	if cfg.Body != "" {
		body = bytes.NewBufferString(cfg.Body)
	}

	req, err := http.NewRequestWithContext(ctx, cfg.EffectiveMethod(), cfg.URL, body)
	if err != nil {
		return Result{}, err
	}
	for name, values := range cfg.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	var timing Timing
	start := time.Now()
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { timing.DNSStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) { timing.DNSDone = time.Now() },
		ConnectStart: func(_, _ string) { timing.ConnectStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) { timing.ConnectDone = time.Now() },
		TLSHandshakeStart: func() { timing.TLSHandshakeStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) { timing.TLSHandshakeDone = time.Now() },
		GotFirstResponseByte: func() { timing.FirstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: cfg.ConnectTimeout,
		}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   cfg.Protocol != ProtocolHTTP11,
		DisableCompression:  false,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: cfg.ConnectTimeout,
	}
	if cfg.Protocol == ProtocolHTTP11 {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: transport}
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	var redirects []Redirect
	if cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				redirects = append(redirects, Redirect{From: via[len(via)-1].URL.String(), To: req.URL.String(), StatusCode: http.StatusFound})
			}
			return nil
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, err
	}
	timing.Total = time.Since(start)

	return Result{
		URL:             resp.Request.URL.String(),
		StatusCode:      resp.StatusCode,
		Protocol:        resp.Proto,
		ResponseHeaders: resp.Header.Clone(),
		Body:            responseBody,
		Timing:          timing,
		Redirects:       redirects,
	}, nil
}
```

- [ ] **Step 5: Wire the real runner in main**

Replace `cmd/icurl/main.go` with:

```go
package main

import (
	"context"
	"os"

	"icurl/internal/cli"
	"icurl/internal/request"
)

func main() {
	code := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{
		Requester: request.NewRunner(),
	})
	os.Exit(code)
}
```

- [ ] **Step 6: Run tests and build**

Run:

```bash
go test ./...
go build ./cmd/icurl
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/icurl/main.go internal/request/result.go internal/request/runner.go internal/request/runner_test.go
git commit -m "Add HTTP request runner"
```

## Task 4: Add Human and JSON Request Reporting

**Files:**
- Create: `internal/report/human.go`
- Create: `internal/report/json.go`
- Create: `internal/report/report_test.go`
- Modify: `internal/cli/app.go`

- [ ] **Step 1: Write report tests**

Create `internal/report/report_test.go`:

```go
package report

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"icurl/internal/request"
)

func TestWriteRequestHumanIncludesHeadersWhenRequested(t *testing.T) {
	var b strings.Builder
	result := request.Result{
		StatusCode:      200,
		Protocol:        "HTTP/1.1",
		ResponseHeaders: http.Header{"Content-Type": []string{"text/plain"}},
		Body:            []byte("hello"),
	}

	if err := WriteRequestHuman(&b, result, RequestHumanOptions{IncludeHeaders: true}); err != nil {
		t.Fatalf("WriteRequestHuman returned error: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "HTTP/1.1 200") {
		t.Fatalf("missing status line: %q", out)
	}
	if !strings.Contains(out, "Content-Type: text/plain") {
		t.Fatalf("missing header: %q", out)
	}
	if !strings.Contains(out, "hello") {
		t.Fatalf("missing body: %q", out)
	}
}

func TestWriteRequestJSONIsStable(t *testing.T) {
	var b strings.Builder
	result := request.Result{StatusCode: 204, Protocol: "HTTP/2.0"}

	if err := WriteRequestJSON(&b, result); err != nil {
		t.Fatalf("WriteRequestJSON returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(b.String()), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded["status_code"].(float64) != 204 {
		t.Fatalf("unexpected status code: %#v", decoded)
	}
	if decoded["protocol"].(string) != "HTTP/2.0" {
		t.Fatalf("unexpected protocol: %#v", decoded)
	}
}
```

- [ ] **Step 2: Run report tests and verify failure**

Run:

```bash
go test ./internal/report -v
```

Expected: FAIL because package `internal/report` has no implementation.

- [ ] **Step 3: Implement human request report**

Create `internal/report/human.go`:

```go
package report

import (
	"fmt"
	"io"
	"sort"

	"icurl/internal/request"
)

type RequestHumanOptions struct {
	IncludeHeaders bool
}

func WriteRequestHuman(w io.Writer, result request.Result, opts RequestHumanOptions) error {
	if opts.IncludeHeaders {
		if _, err := fmt.Fprintf(w, "%s %d\n", result.Protocol, result.StatusCode); err != nil {
			return err
		}
		names := make([]string, 0, len(result.ResponseHeaders))
		for name := range result.ResponseHeaders {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, value := range result.ResponseHeaders.Values(name) {
				if _, err := fmt.Fprintf(w, "%s: %s\n", name, value); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	_, err := w.Write(result.Body)
	return err
}
```

- [ ] **Step 4: Implement JSON request report**

Create `internal/report/json.go`:

```go
package report

import (
	"encoding/base64"
	"encoding/json"
	"io"

	"icurl/internal/request"
)

type requestJSON struct {
	URL        string              `json:"url"`
	StatusCode int                 `json:"status_code"`
	Protocol   string              `json:"protocol"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64"`
	Redirects  []request.Redirect  `json:"redirects"`
}

func WriteRequestJSON(w io.Writer, result request.Result) error {
	payload := requestJSON{
		URL:        result.URL,
		StatusCode: result.StatusCode,
		Protocol:   result.Protocol,
		Headers:    map[string][]string(result.ResponseHeaders),
		BodyBase64: base64.StdEncoding.EncodeToString(result.Body),
		Redirects:  result.Redirects,
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}
```

- [ ] **Step 5: Wire reports into CLI**

In `internal/cli/app.go`, add import:

```go
"icurl/internal/report"
```

Replace:

```go
fmt.Fprintf(stdout, "HTTP %d %s\n", result.StatusCode, result.Protocol)
return 0
```

With:

```go
if cfg.JSON {
	if err := report.WriteRequestJSON(stdout, result); err != nil {
		fmt.Fprintf(stderr, "icurl: %v\n", err)
		return 1
	}
	return 0
}
if err := report.WriteRequestHuman(stdout, result, report.RequestHumanOptions{IncludeHeaders: cfg.IncludeHeaders}); err != nil {
	fmt.Fprintf(stderr, "icurl: %v\n", err)
	return 1
}
return 0
```

- [ ] **Step 6: Run tests and build**

Run:

```bash
go test ./...
go build ./cmd/icurl
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/report/human.go internal/report/json.go internal/report/report_test.go internal/cli/app.go
git commit -m "Add request report renderers"
```

## Task 5: Add HTTP/3 Request Path

**Files:**
- Modify: `go.mod`
- Modify: `internal/request/runner.go`
- Modify: `internal/request/runner_test.go`

- [ ] **Step 1: Add quic-go dependency**

Run:

```bash
go get github.com/quic-go/quic-go/http3
```

Expected: `go.mod` and `go.sum` include `github.com/quic-go/quic-go`.

- [ ] **Step 2: Write HTTP/3 transport selection test**

Append to `internal/request/runner_test.go`:

```go
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRunnerUsesHTTP3TransportWhenForced(t *testing.T) {
	runner := NewRunner()
	runner.newHTTP3RoundTripper = func(cfg Config) (http.RoundTripper, func() error, error) {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Proto:      "HTTP/3.0",
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("h3")),
				Request:    req,
			}, nil
		}), func() error { return nil }, nil
	}

	result, err := runner.Do(context.Background(), Config{
		URL:      "https://example.com",
		Protocol: ProtocolHTTP3Only,
		MaxTime:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	if result.Protocol != "HTTP/3.0" {
		t.Fatalf("expected HTTP/3.0, got %q", result.Protocol)
	}
	if strings.TrimSpace(string(result.Body)) != "h3" {
		t.Fatalf("unexpected body %q", string(result.Body))
	}
}
```

Add `io` to the test imports.

- [ ] **Step 3: Run the new test and verify failure**

Run:

```bash
go test ./internal/request -run TestRunnerUsesHTTP3TransportWhenForced -v
```

Expected: FAIL because `newHTTP3RoundTripper` is missing and HTTP/3 is not implemented.

- [ ] **Step 4: Implement HTTP/3 round trip path**

Modify `internal/request/runner.go`.

Add imports:

```go
"github.com/quic-go/quic-go/http3"
```

Change `Runner` to:

```go
type Runner struct {
	newHTTP3RoundTripper func(Config) (http.RoundTripper, func() error, error)
}

func NewRunner() *Runner {
	r := &Runner{}
	r.newHTTP3RoundTripper = r.defaultHTTP3RoundTripper
	return r
}
```

Replace the start of `Do` with:

```go
func (r *Runner) Do(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Protocol == ProtocolHTTP3 || cfg.Protocol == ProtocolHTTP3Only {
		return r.doHTTP3(ctx, cfg)
	}
	return r.doHTTP(ctx, cfg)
}
```

Add:

```go
func (r *Runner) doHTTP3(ctx context.Context, cfg Config) (Result, error) {
	transport, closeTransport, err := r.newHTTP3RoundTripper(cfg)
	if err != nil {
		return Result{}, err
	}
	defer closeTransport()
	return r.doWithRoundTripper(ctx, cfg, transport)
}

func (r *Runner) defaultHTTP3RoundTripper(cfg Config) (http.RoundTripper, func() error, error) {
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	return transport, transport.Close, nil
}
```

Refactor `doHTTP` so request execution is shared:

```go
func (r *Runner) doHTTP(ctx context.Context, cfg Config) (Result, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: cfg.ConnectTimeout,
		}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   cfg.Protocol != ProtocolHTTP11,
		DisableCompression:  false,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: cfg.ConnectTimeout,
	}
	if cfg.Protocol == ProtocolHTTP11 {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return r.doWithRoundTripper(ctx, cfg, transport)
}
```

Move the existing request creation, httptrace setup, client execution, response read, and `Result` construction into:

```go
func (r *Runner) doWithRoundTripper(ctx context.Context, cfg Config, transport http.RoundTripper) (Result, error) {
	if cfg.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.MaxTime)
		defer cancel()
	}

	var body io.Reader
	if cfg.Body != "" {
		body = bytes.NewBufferString(cfg.Body)
	}

	req, err := http.NewRequestWithContext(ctx, cfg.EffectiveMethod(), cfg.URL, body)
	if err != nil {
		return Result{}, err
	}
	for name, values := range cfg.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	var timing Timing
	start := time.Now()
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { timing.DNSStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) { timing.DNSDone = time.Now() },
		ConnectStart: func(_, _ string) { timing.ConnectStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) { timing.ConnectDone = time.Now() },
		TLSHandshakeStart: func() { timing.TLSHandshakeStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) { timing.TLSHandshakeDone = time.Now() },
		GotFirstResponseByte: func() { timing.FirstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{Transport: transport}
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if cfg.Protocol == ProtocolHTTP3 {
			fallback := cfg
			fallback.Protocol = ProtocolAuto
			return r.doHTTP(ctx, fallback)
		}
		return Result{}, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, err
	}
	timing.Total = time.Since(start)

	return Result{
		URL:             resp.Request.URL.String(),
		StatusCode:      resp.StatusCode,
		Protocol:        resp.Proto,
		ResponseHeaders: resp.Header.Clone(),
		Body:            responseBody,
		Timing:          timing,
	}, nil
}
```

- [ ] **Step 5: Run HTTP/3 test and full tests**

Run:

```bash
go test ./internal/request -run TestRunnerUsesHTTP3TransportWhenForced -v
go test ./...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/request/runner.go internal/request/runner_test.go
git commit -m "Add HTTP3 request path"
```

## Task 6: Add Evidence Types and Classifier Rules

**Files:**
- Create: `internal/evidence/evidence.go`
- Create: `internal/evidence/evidence_test.go`
- Create: `internal/classifier/classifier.go`
- Create: `internal/classifier/classifier_test.go`

- [ ] **Step 1: Write evidence JSON stability test**

Create `internal/evidence/evidence_test.go`:

```go
package evidence

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProbeResultJSONFields(t *testing.T) {
	result := ProbeResult{
		ProbeName:    "TLSHandshake",
		Layer:        LayerTLS,
		Target:       "example.com:443",
		Result:       ResultFailed,
		ErrorKind:    ErrorReset,
		ErrorMessage: "connection reset before certificate",
		Duration:     10 * time.Millisecond,
		Observations: []string{"TCP connect succeeded"},
		Confidence:   ConfidenceObserved,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if decoded["probe_name"] != "TLSHandshake" {
		t.Fatalf("unexpected probe_name: %#v", decoded)
	}
	if decoded["layer"] != "TLS" {
		t.Fatalf("unexpected layer: %#v", decoded)
	}
}
```

- [ ] **Step 2: Run evidence test and verify failure**

Run:

```bash
go test ./internal/evidence -v
```

Expected: FAIL because evidence types are missing.

- [ ] **Step 3: Implement evidence types**

Create `internal/evidence/evidence.go`:

```go
package evidence

import "time"

type Layer string

const (
	LayerDNS   Layer = "DNS"
	LayerTCP   Layer = "TCP"
	LayerTLS   Layer = "TLS"
	LayerHTTP  Layer = "HTTP"
	LayerUDP   Layer = "UDP"
	LayerQUIC  Layer = "QUIC"
	LayerLocal Layer = "LOCAL"
)

type Result string

const (
	ResultOK      Result = "OK"
	ResultFailed  Result = "FAILED"
	ResultTimeout Result = "TIMEOUT"
	ResultSkipped Result = "SKIPPED"
)

type ErrorKind string

const (
	ErrorNone            ErrorKind = "NONE"
	ErrorTimeout         ErrorKind = "TIMEOUT"
	ErrorRefused         ErrorKind = "REFUSED"
	ErrorReset           ErrorKind = "RESET"
	ErrorUnreachable     ErrorKind = "UNREACHABLE"
	ErrorCertificate     ErrorKind = "CERTIFICATE"
	ErrorProtocol        ErrorKind = "PROTOCOL"
	ErrorSuspiciousDNS   ErrorKind = "SUSPICIOUS_DNS"
	ErrorPermission      ErrorKind = "PERMISSION"
	ErrorUnknown         ErrorKind = "UNKNOWN"
)

type Confidence string

const (
	ConfidenceObserved Confidence = "observed"
	ConfidenceInferred Confidence = "inferred"
)

type AssessmentLevel string

const (
	AssessmentPass             AssessmentLevel = "PASS"
	AssessmentFail             AssessmentLevel = "FAIL"
	AssessmentSuspiciousLow    AssessmentLevel = "SUSPICIOUS_LOW"
	AssessmentSuspiciousMedium AssessmentLevel = "SUSPICIOUS_MEDIUM"
	AssessmentSuspiciousHigh   AssessmentLevel = "SUSPICIOUS_HIGH"
	AssessmentUnknown          AssessmentLevel = "UNKNOWN"
)

type ProbeResult struct {
	ProbeName     string        `json:"probe_name"`
	Layer         Layer         `json:"layer"`
	Target        string        `json:"target"`
	RemoteAddress string        `json:"remote_address,omitempty"`
	LocalAddress  string        `json:"local_address,omitempty"`
	StartedAt     time.Time     `json:"started_at,omitempty"`
	FinishedAt    time.Time     `json:"finished_at,omitempty"`
	Duration      time.Duration `json:"duration_ns"`
	Result        Result        `json:"result"`
	ErrorKind     ErrorKind     `json:"error_kind"`
	ErrorMessage  string        `json:"error_message,omitempty"`
	Observations  []string      `json:"observations,omitempty"`
	Confidence    Confidence    `json:"confidence"`
}

type Assessment struct {
	Level     AssessmentLevel `json:"level"`
	Category  string          `json:"category"`
	Summary   string          `json:"summary"`
	Reasons   []string        `json:"reasons"`
	NextSteps []string        `json:"next_steps"`
}
```

- [ ] **Step 4: Run evidence tests**

Run:

```bash
go test ./internal/evidence -v
```

Expected: PASS.

- [ ] **Step 5: Write classifier tests**

Create `internal/classifier/classifier_test.go`:

```go
package classifier

import (
	"testing"

	"icurl/internal/evidence"
)

func TestClassifyDNSInterferencePattern(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "DNS", Layer: evidence.LayerDNS, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorSuspiciousDNS, Observations: []string{"system resolver returned reserved address"}},
		{ProbeName: "TCP", Layer: evidence.LayerTCP, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorTimeout},
	})
	if assessment.Level != evidence.AssessmentSuspiciousHigh {
		t.Fatalf("expected suspicious high, got %#v", assessment)
	}
	if assessment.Category != "DNS_INTERFERENCE_PATTERN" {
		t.Fatalf("unexpected category %q", assessment.Category)
	}
}

func TestClassifyTLSInterruptionPattern(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "TCP", Layer: evidence.LayerTCP, Result: evidence.ResultOK},
		{ProbeName: "TLS", Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorReset, Observations: []string{"no certificate received"}},
	})
	if assessment.Level != evidence.AssessmentSuspiciousHigh {
		t.Fatalf("expected suspicious high, got %#v", assessment)
	}
	if assessment.Category != "TLS_SNI_INTERRUPTION_PATTERN" {
		t.Fatalf("unexpected category %q", assessment.Category)
	}
}

func TestClassifyHTTPOriginFailure(t *testing.T) {
	assessment := Classify([]evidence.ProbeResult{
		{ProbeName: "DNS", Layer: evidence.LayerDNS, Result: evidence.ResultOK},
		{ProbeName: "TCP", Layer: evidence.LayerTCP, Result: evidence.ResultOK},
		{ProbeName: "TLS", Layer: evidence.LayerTLS, Result: evidence.ResultOK},
		{ProbeName: "HTTP", Layer: evidence.LayerHTTP, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorProtocol, ErrorMessage: "HTTP 403"},
	})
	if assessment.Level != evidence.AssessmentFail {
		t.Fatalf("expected fail, got %#v", assessment)
	}
	if assessment.Category != "HTTP_ORIGIN_FAILURE" {
		t.Fatalf("unexpected category %q", assessment.Category)
	}
}
```

- [ ] **Step 6: Run classifier tests and verify failure**

Run:

```bash
go test ./internal/classifier -v
```

Expected: FAIL because classifier is missing.

- [ ] **Step 7: Implement classifier**

Create `internal/classifier/classifier.go`:

```go
package classifier

import "icurl/internal/evidence"

func Classify(results []evidence.ProbeResult) evidence.Assessment {
	if has(results, evidence.LayerDNS, evidence.ResultFailed, evidence.ErrorSuspiciousDNS) {
		return evidence.Assessment{
			Level:    evidence.AssessmentSuspiciousHigh,
			Category: "DNS_INTERFERENCE_PATTERN",
			Summary:  "DNS results show suspicious resolver behavior.",
			Reasons:  collectReasons(results),
			NextSteps: []string{"Compare with another resolver", "Run deep diagnostics if the failure is repeatable"},
		}
	}

	if layerOK(results, evidence.LayerTCP) && has(results, evidence.LayerTLS, evidence.ResultFailed, evidence.ErrorReset) {
		return evidence.Assessment{
			Level:    evidence.AssessmentSuspiciousHigh,
			Category: "TLS_SNI_INTERRUPTION_PATTERN",
			Summary:  "TCP connects, but TLS is interrupted before a complete handshake.",
			Reasons:  collectReasons(results),
			NextSteps: []string{"Retry with diagnose --deep", "Compare behavior with HTTP/3 if the target supports it"},
		}
	}

	if layerOK(results, evidence.LayerTCP) && layerOK(results, evidence.LayerTLS) && has(results, evidence.LayerQUIC, evidence.ResultTimeout, evidence.ErrorTimeout) {
		return evidence.Assessment{
			Level:    evidence.AssessmentSuspiciousMedium,
			Category: "UDP_QUIC_BLOCKAGE_PATTERN",
			Summary:  "TCP/TLS works, but QUIC over UDP does not respond.",
			Reasons:  collectReasons(results),
			NextSteps: []string{"Retry with --http3-only", "Check whether the server advertises HTTP/3"},
		}
	}

	if layerOK(results, evidence.LayerDNS) && layerOK(results, evidence.LayerTCP) && layerOK(results, evidence.LayerTLS) && layerFailed(results, evidence.LayerHTTP) {
		return evidence.Assessment{
			Level:    evidence.AssessmentFail,
			Category: "HTTP_ORIGIN_FAILURE",
			Summary:  "The network path works through TLS; the failure is at HTTP layer.",
			Reasons:  collectReasons(results),
			NextSteps: []string{"Inspect status code and response headers"},
		}
	}

	if allOK(results) {
		return evidence.Assessment{Level: evidence.AssessmentPass, Category: "PASS", Summary: "All probes succeeded."}
	}

	return evidence.Assessment{
		Level:     evidence.AssessmentUnknown,
		Category:  "INSUFFICIENT_EVIDENCE",
		Summary:   "The collected evidence does not identify a specific failure pattern.",
		Reasons:   collectReasons(results),
		NextSteps: []string{"Retry diagnostics", "Run deep diagnostics for packet-level evidence"},
	}
}

func has(results []evidence.ProbeResult, layer evidence.Layer, result evidence.Result, kind evidence.ErrorKind) bool {
	for _, r := range results {
		if r.Layer == layer && r.Result == result && r.ErrorKind == kind {
			return true
		}
	}
	return false
}

func layerOK(results []evidence.ProbeResult, layer evidence.Layer) bool {
	for _, r := range results {
		if r.Layer == layer && r.Result == evidence.ResultOK {
			return true
		}
	}
	return false
}

func layerFailed(results []evidence.ProbeResult, layer evidence.Layer) bool {
	for _, r := range results {
		if r.Layer == layer && r.Result == evidence.ResultFailed {
			return true
		}
	}
	return false
}

func allOK(results []evidence.ProbeResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if r.Result != evidence.ResultOK && r.Result != evidence.ResultSkipped {
			return false
		}
	}
	return true
}

func collectReasons(results []evidence.ProbeResult) []string {
	reasons := make([]string, 0)
	for _, r := range results {
		if r.ErrorMessage != "" {
			reasons = append(reasons, r.ProbeName+": "+r.ErrorMessage)
		}
		for _, observation := range r.Observations {
			reasons = append(reasons, r.ProbeName+": "+observation)
		}
	}
	return reasons
}
```

- [ ] **Step 8: Run tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/evidence/evidence.go internal/evidence/evidence_test.go internal/classifier/classifier.go internal/classifier/classifier_test.go
git commit -m "Add diagnostic evidence classifier"
```

## Task 7: Add DNS, TCP, and TLS Probes

**Files:**
- Create: `internal/probe/probe.go`
- Create: `internal/probe/dns/dns.go`
- Create: `internal/probe/dns/dns_test.go`
- Create: `internal/probe/tcp/tcp.go`
- Create: `internal/probe/tcp/tcp_test.go`
- Create: `internal/probe/tls/tls.go`
- Create: `internal/probe/tls/tls_test.go`

- [ ] **Step 1: Create shared probe interfaces**

Create `internal/probe/probe.go`:

```go
package probe

import (
	"context"
	"net"
	"net/url"

	"icurl/internal/evidence"
)

type Target struct {
	URL  *url.URL
	Host string
	Port string
	IPs  []net.IP
}

type Probe interface {
	Run(context.Context, Target) evidence.ProbeResult
}
```

- [ ] **Step 2: Write DNS probe tests**

Create `internal/probe/dns/dns_test.go`:

```go
package dns

import (
	"context"
	"net"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type fakeResolver struct {
	ips []net.IP
	err error
}

func (f fakeResolver) LookupIP(ctx context.Context, network string, host string) ([]net.IP, error) {
	return f.ips, f.err
}

func TestProbeFlagsReservedPublicAnswer(t *testing.T) {
	p := Probe{Resolver: fakeResolver{ips: []net.IP{net.ParseIP("203.0.113.10")}}}
	result := p.Run(context.Background(), probe.Target{Host: "example.com"})

	if result.Result != evidence.ResultFailed {
		t.Fatalf("expected failed result, got %#v", result)
	}
	if result.ErrorKind != evidence.ErrorSuspiciousDNS {
		t.Fatalf("expected suspicious DNS, got %#v", result)
	}
}

func TestProbeAcceptsPublicAnswer(t *testing.T) {
	p := Probe{Resolver: fakeResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}}
	result := p.Run(context.Background(), probe.Target{Host: "example.com"})

	if result.Result != evidence.ResultOK {
		t.Fatalf("expected OK, got %#v", result)
	}
}
```

- [ ] **Step 3: Implement DNS probe**

Create `internal/probe/dns/dns.go`:

```go
package dns

import (
	"context"
	"net"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type Resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type netResolver struct{}

func (netResolver) LookupIP(ctx context.Context, network string, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

type Probe struct {
	Resolver Resolver
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	resolver := p.Resolver
	if resolver == nil {
		resolver = netResolver{}
	}
	start := time.Now()
	ips, err := resolver.LookupIP(ctx, "ip", target.Host)
	finished := time.Now()
	result := evidence.ProbeResult{
		ProbeName:  "DNS",
		Layer:      evidence.LayerDNS,
		Target:     target.Host,
		StartedAt:  start,
		FinishedAt: finished,
		Duration:   finished.Sub(start),
		Confidence: evidence.ConfidenceObserved,
	}
	if err != nil {
		result.Result = evidence.ResultFailed
		result.ErrorKind = evidence.ErrorUnknown
		result.ErrorMessage = err.Error()
		return result
	}
	if len(ips) == 0 {
		result.Result = evidence.ResultFailed
		result.ErrorKind = evidence.ErrorUnknown
		result.ErrorMessage = "resolver returned no addresses"
		return result
	}
	for _, ip := range ips {
		if isSuspiciousPublicAnswer(ip) {
			result.Result = evidence.ResultFailed
			result.ErrorKind = evidence.ErrorSuspiciousDNS
			result.Observations = []string{"resolver returned reserved or non-routable address " + ip.String()}
			return result
		}
		result.Observations = append(result.Observations, "resolved "+ip.String())
	}
	result.Result = evidence.ResultOK
	result.ErrorKind = evidence.ErrorNone
	return result
}

func isSuspiciousPublicAnswer(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified() || isDocumentationRange(ip)
}

func isDocumentationRange(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return (v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
		(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
		(v4[0] == 203 && v4[1] == 0 && v4[2] == 113)
}
```

- [ ] **Step 4: Write TCP probe tests**

Create `internal/probe/tcp/tcp_test.go`:

```go
package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

func TestProbeConnectsToLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	result := Probe{Timeout: time.Second}.Run(context.Background(), probe.Target{Host: host, Port: port})
	if result.Result != evidence.ResultOK {
		t.Fatalf("expected OK, got %#v", result)
	}
}
```

- [ ] **Step 5: Implement TCP probe**

Create `internal/probe/tcp/tcp.go`:

```go
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
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	address := net.JoinHostPort(target.Host, target.Port)
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	finished := time.Now()
	result := evidence.ProbeResult{
		ProbeName:  "TCPConnect",
		Layer:      evidence.LayerTCP,
		Target:     address,
		StartedAt:  start,
		FinishedAt: finished,
		Duration:   finished.Sub(start),
		Confidence: evidence.ConfidenceObserved,
	}
	if err != nil {
		result.Result = evidence.ResultFailed
		result.ErrorKind = classifyError(err)
		result.ErrorMessage = err.Error()
		return result
	}
	defer conn.Close()
	result.Result = evidence.ResultOK
	result.ErrorKind = evidence.ErrorNone
	result.RemoteAddress = conn.RemoteAddr().String()
	result.LocalAddress = conn.LocalAddr().String()
	result.Observations = []string{"TCP connect succeeded"}
	return result
}

func classifyError(err error) evidence.ErrorKind {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return evidence.ErrorTimeout
	}
	return evidence.ErrorUnknown
}
```

- [ ] **Step 6: Write TLS probe tests**

Create `internal/probe/tls/tls_test.go`:

```go
package tlsprobe

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

func TestProbeNegotiatesALPN(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCertPEM, localhostKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair returned error: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatalf("tls.Listen returned error: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort returned error: %v", err)
	}
	result := Probe{Timeout: time.Second, InsecureSkipVerify: true}.Run(context.Background(), probe.Target{Host: host, Port: port})
	if result.Result != evidence.ResultOK {
		t.Fatalf("expected OK, got %#v", result)
	}
}
```

Use a local self-signed certificate in the same test file:

```go
var localhostCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBjTCCATOgAwIBAgIRAKYG6xCjF1qzKXKf3YhZ4yYwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEChMHdGVzdGluZzAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBa
MBIxEDAOBgNVBAoTB3Rlc3RpbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASf
3iZzW3i0P2h6UCOHhbyB7u6N2iTBGSEI4umvcoT0zXzVdKzA7f8gZlci7kGxgtGs
L4Rr+0p0s86jPM61nCIgo1MwUTAdBgNVHQ4EFgQUd6n8F5WqU8ugD0N7wLq7kU7Y
5vYwHwYDVR0jBBgwFoAUd6n8F5WqU8ugD0N7wLq7kU7Y5vYwDwYDVR0TAQH/BAUw
AwEB/zAKBggqhkjOPQQDAgNIADBFAiB8x+pqvW1MZ0T+xjV+8Ww+5YyWlq1x0xUK
I0xvYxYd7wIhANJzctar3YWX1nOwQIlYg3VccdtUuUSlO0gMuFzLk3a8
-----END CERTIFICATE-----`)

var localhostKeyPEM = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGK8w0Lx3kOPGVuGRP14Q7ZiyfJb7fIabE86X4VxVjMjoAoGCCqGSM49
AwEHoUQDQgAEn94mc1t4tD9oelAjh4W8ge7ujdokwRkhCOLpr3KE9M181XSswO3/
IGZXIu5BsYLRrC+Ea/tKdLPOozzOtZwiIA==
-----END EC PRIVATE KEY-----`)
```

- [ ] **Step 7: Implement TLS probe**

Create `internal/probe/tls/tls.go`:

```go
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
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	address := net.JoinHostPort(target.Host, target.Port)
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		finished := time.Now()
		return evidence.ProbeResult{ProbeName: "TLSHandshake", Layer: evidence.LayerTLS, Target: address, StartedAt: start, FinishedAt: finished, Duration: finished.Sub(start), Result: evidence.ResultFailed, ErrorKind: evidence.ErrorUnknown, ErrorMessage: err.Error(), Confidence: evidence.ConfidenceObserved}
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{ServerName: target.Host, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12, InsecureSkipVerify: p.InsecureSkipVerify})
	err = tlsConn.HandshakeContext(ctx)
	finished := time.Now()
	result := evidence.ProbeResult{ProbeName: "TLSHandshake", Layer: evidence.LayerTLS, Target: address, StartedAt: start, FinishedAt: finished, Duration: finished.Sub(start), Confidence: evidence.ConfidenceObserved}
	if err != nil {
		result.Result = evidence.ResultFailed
		result.ErrorKind = evidence.ErrorReset
		result.ErrorMessage = err.Error()
		result.Observations = []string{"TLS handshake did not complete"}
		return result
	}
	state := tlsConn.ConnectionState()
	result.Result = evidence.ResultOK
	result.ErrorKind = evidence.ErrorNone
	result.Observations = []string{"TLS handshake succeeded", "ALPN " + state.NegotiatedProtocol}
	return result
}
```

- [ ] **Step 8: Run probe tests**

Run:

```bash
go test ./internal/probe/... 
```

Expected: PASS. If the embedded certificate fails to parse, replace the test certificate by generating one with `httptest.NewTLSServer` and using its listener address for the TLS probe.

- [ ] **Step 9: Commit**

```bash
git add internal/probe/probe.go internal/probe/dns/dns.go internal/probe/dns/dns_test.go internal/probe/tcp/tcp.go internal/probe/tcp/tcp_test.go internal/probe/tls/tls.go internal/probe/tls/tls_test.go
git commit -m "Add DNS TCP and TLS probes"
```

## Task 8: Add HTTP and QUIC Probe Wrappers

**Files:**
- Create: `internal/probe/http/http.go`
- Create: `internal/probe/http/http_test.go`
- Create: `internal/probe/quic/quic.go`
- Create: `internal/probe/quic/quic_test.go`

- [ ] **Step 1: Write HTTP probe test**

Create `internal/probe/http/http_test.go`:

```go
package httpprobe

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
	"icurl/internal/request"
)

type fakeRunner struct {
	result request.Result
	err    error
}

func (f fakeRunner) Do(ctx context.Context, cfg request.Config) (request.Result, error) {
	return f.result, f.err
}

func TestProbeReportsHTTPStatusFailure(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	p := Probe{Runner: fakeRunner{result: request.Result{StatusCode: http.StatusForbidden, Protocol: "HTTP/2.0"}}}
	result := p.Run(context.Background(), probe.Target{URL: u, Host: "example.com", Port: "443"})

	if result.Result != evidence.ResultFailed {
		t.Fatalf("expected failed HTTP result, got %#v", result)
	}
	if result.ErrorKind != evidence.ErrorProtocol {
		t.Fatalf("expected protocol error, got %#v", result)
	}
}
```

- [ ] **Step 2: Implement HTTP probe**

Create `internal/probe/http/http.go`:

```go
package httpprobe

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
	"icurl/internal/request"
)

type Runner interface {
	Do(context.Context, request.Config) (request.Result, error)
}

type Probe struct {
	Runner Runner
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	start := time.Now()
	result, err := p.Runner.Do(ctx, request.Config{URL: target.URL.String(), Method: http.MethodHead, Protocol: request.ProtocolAuto, MaxTime: 10 * time.Second, ConnectTimeout: 5 * time.Second})
	finished := time.Now()
	probeResult := evidence.ProbeResult{ProbeName: "HTTP", Layer: evidence.LayerHTTP, Target: target.URL.String(), StartedAt: start, FinishedAt: finished, Duration: finished.Sub(start), Confidence: evidence.ConfidenceObserved}
	if err != nil {
		probeResult.Result = evidence.ResultFailed
		probeResult.ErrorKind = evidence.ErrorProtocol
		probeResult.ErrorMessage = err.Error()
		return probeResult
	}
	if result.StatusCode >= 400 {
		probeResult.Result = evidence.ResultFailed
		probeResult.ErrorKind = evidence.ErrorProtocol
		probeResult.ErrorMessage = fmt.Sprintf("HTTP %d", result.StatusCode)
		probeResult.Observations = []string{"HTTP responded with " + result.Protocol}
		return probeResult
	}
	probeResult.Result = evidence.ResultOK
	probeResult.ErrorKind = evidence.ErrorNone
	probeResult.Observations = []string{fmt.Sprintf("HTTP %d over %s", result.StatusCode, result.Protocol)}
	return probeResult
}
```

- [ ] **Step 3: Write QUIC probe test**

Create `internal/probe/quic/quic_test.go`:

```go
package quicprobe

import (
	"context"
	"net/url"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
	"icurl/internal/request"
)

type fakeRunner struct {
	result request.Result
	err    error
}

func (f fakeRunner) Do(ctx context.Context, cfg request.Config) (request.Result, error) {
	return f.result, f.err
}

func TestProbeReportsHTTP3Success(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	p := Probe{Runner: fakeRunner{result: request.Result{StatusCode: 200, Protocol: "HTTP/3.0"}}}
	result := p.Run(context.Background(), probe.Target{URL: u, Host: "example.com", Port: "443"})

	if result.Result != evidence.ResultOK {
		t.Fatalf("expected OK, got %#v", result)
	}
	if result.Layer != evidence.LayerQUIC {
		t.Fatalf("expected QUIC layer, got %#v", result)
	}
}
```

- [ ] **Step 4: Implement QUIC probe**

Create `internal/probe/quic/quic.go`:

```go
package quicprobe

import (
	"context"
	"time"

	"icurl/internal/evidence"
	"icurl/internal/probe"
	"icurl/internal/request"
)

type Runner interface {
	Do(context.Context, request.Config) (request.Result, error)
}

type Probe struct {
	Runner Runner
}

func (p Probe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	start := time.Now()
	result, err := p.Runner.Do(ctx, request.Config{URL: target.URL.String(), Protocol: request.ProtocolHTTP3Only, MaxTime: 10 * time.Second, ConnectTimeout: 5 * time.Second})
	finished := time.Now()
	probeResult := evidence.ProbeResult{ProbeName: "QUICHTTP3", Layer: evidence.LayerQUIC, Target: target.URL.String(), StartedAt: start, FinishedAt: finished, Duration: finished.Sub(start), Confidence: evidence.ConfidenceObserved}
	if err != nil {
		probeResult.Result = evidence.ResultTimeout
		probeResult.ErrorKind = evidence.ErrorTimeout
		probeResult.ErrorMessage = err.Error()
		probeResult.Observations = []string{"HTTP/3 over QUIC did not complete"}
		return probeResult
	}
	probeResult.Result = evidence.ResultOK
	probeResult.ErrorKind = evidence.ErrorNone
	probeResult.Observations = []string{"HTTP/3 request succeeded over " + result.Protocol}
	return probeResult
}
```

- [ ] **Step 5: Run probe wrapper tests**

Run:

```bash
go test ./internal/probe/http ./internal/probe/quic -v
go test ./...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/probe/http/http.go internal/probe/http/http_test.go internal/probe/quic/quic.go internal/probe/quic/quic_test.go
git commit -m "Add HTTP and QUIC diagnostic probes"
```

## Task 9: Add Diagnostic Engine and Diagnose CLI Command

**Files:**
- Create: `internal/diagnose/engine.go`
- Create: `internal/diagnose/engine_test.go`
- Modify: `internal/cli/app.go`
- Modify: `cmd/icurl/main.go`

- [ ] **Step 1: Write diagnostic engine test**

Create `internal/diagnose/engine_test.go`:

```go
package diagnose

import (
	"context"
	"net/url"
	"testing"

	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type fakeProbe struct {
	result evidence.ProbeResult
}

func (f fakeProbe) Run(ctx context.Context, target probe.Target) evidence.ProbeResult {
	return f.result
}

func TestEngineRunsProbesAndClassifies(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	engine := Engine{Probes: []probe.Probe{
		fakeProbe{result: evidence.ProbeResult{ProbeName: "TCP", Layer: evidence.LayerTCP, Result: evidence.ResultOK}},
		fakeProbe{result: evidence.ProbeResult{ProbeName: "TLS", Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorKind: evidence.ErrorReset, Observations: []string{"no certificate received"}}},
	}}

	result := engine.Run(context.Background(), Config{URL: u})
	if len(result.ProbeResults) != 2 {
		t.Fatalf("expected two probe results, got %d", len(result.ProbeResults))
	}
	if result.Assessment.Category != "TLS_SNI_INTERRUPTION_PATTERN" {
		t.Fatalf("unexpected assessment %#v", result.Assessment)
	}
}
```

- [ ] **Step 2: Implement diagnostic engine**

Create `internal/diagnose/engine.go`:

```go
package diagnose

import (
	"context"
	"net"
	"net/url"

	"icurl/internal/classifier"
	"icurl/internal/evidence"
	"icurl/internal/probe"
)

type Config struct {
	URL  *url.URL
	Deep bool
}

type Result struct {
	Target       string                 `json:"target"`
	ProbeResults []evidence.ProbeResult `json:"probe_results"`
	Assessment   evidence.Assessment    `json:"assessment"`
	CapturePath  string                 `json:"capture_path,omitempty"`
}

type Engine struct {
	Probes []probe.Probe
}

func (e Engine) Run(ctx context.Context, cfg Config) Result {
	port := cfg.URL.Port()
	if port == "" {
		port = defaultPort(cfg.URL.Scheme)
	}
	target := probe.Target{URL: cfg.URL, Host: cfg.URL.Hostname(), Port: port, IPs: []net.IP{}}
	results := make([]evidence.ProbeResult, 0, len(e.Probes))
	for _, p := range e.Probes {
		results = append(results, p.Run(ctx, target))
	}
	return Result{Target: cfg.URL.String(), ProbeResults: results, Assessment: classifier.Classify(results)}
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}
```

- [ ] **Step 3: Run diagnostic engine tests**

Run:

```bash
go test ./internal/diagnose -v
```

Expected: PASS.

- [ ] **Step 4: Add diagnose dependencies to CLI**

Modify `internal/cli/app.go`.

Add imports:

```go
"net/url"
"icurl/internal/diagnose"
```

Add interface and dependency field:

```go
type Diagnoser interface {
	Run(context.Context, diagnose.Config) diagnose.Result
}
```

Change `Dependencies` to:

```go
type Dependencies struct {
	Requester Requester
	Diagnoser Diagnoser
}
```

Replace the diagnose branch in `Run` with:

```go
if args[0] == "diagnose" {
	return runDiagnose(ctx, args[1:], stdout, stderr, deps)
}
```

Add:

```go
func runDiagnose(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps Dependencies) int {
	fs := flag.NewFlagSet("icurl diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var deep bool
	var jsonOut bool
	fs.BoolVar(&deep, "deep", false, "run deep diagnostics")
	fs.BoolVar(&jsonOut, "json", false, "write JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "icurl: diagnose expects exactly one URL")
		return 2
	}
	parsed, err := url.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "icurl: invalid URL: %v\n", err)
		return 2
	}
	if deps.Diagnoser == nil {
		fmt.Fprintln(stderr, "icurl: diagnoser dependency is not configured")
		return 2
	}
	result := deps.Diagnoser.Run(ctx, diagnose.Config{URL: parsed, Deep: deep})
	if jsonOut {
		fmt.Fprintf(stdout, "%+v\n", result)
		return 0
	}
	fmt.Fprintf(stdout, "Assessment: %s %s\n", result.Assessment.Level, result.Assessment.Category)
	return 0
}
```

This temporary output is replaced by report renderers in Task 10.

- [ ] **Step 5: Wire real diagnostic engine in main**

Modify `cmd/icurl/main.go` imports to include:

```go
"icurl/internal/diagnose"
httpprobe "icurl/internal/probe/http"
quicprobe "icurl/internal/probe/quic"
dnsprobe "icurl/internal/probe/dns"
tcpprobe "icurl/internal/probe/tcp"
tlsprobe "icurl/internal/probe/tls"
```

Replace the dependency construction with:

```go
runner := request.NewRunner()
engine := diagnose.Engine{Probes: []probe.Probe{
	dnsprobe.Probe{},
	tcpprobe.Probe{},
	tlsprobe.Probe{},
	httpprobe.Probe{Runner: runner},
	quicprobe.Probe{Runner: runner},
}}
code := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{
	Requester: runner,
	Diagnoser: engine,
})
```

Add import:

```go
"icurl/internal/probe"
```

- [ ] **Step 6: Run full tests and build**

Run:

```bash
go test ./...
go build ./cmd/icurl
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/diagnose/engine.go internal/diagnose/engine_test.go internal/cli/app.go cmd/icurl/main.go
git commit -m "Add diagnostic engine command"
```

## Task 10: Add Diagnostic Human and JSON Reports

**Files:**
- Modify: `internal/report/human.go`
- Modify: `internal/report/json.go`
- Modify: `internal/report/report_test.go`
- Modify: `internal/cli/app.go`

- [ ] **Step 1: Write diagnostic report tests**

Append to `internal/report/report_test.go`:

```go
func TestWriteDiagnoseHumanIncludesAssessmentAndLayers(t *testing.T) {
	var b strings.Builder
	result := diagnose.Result{
		Target: "https://example.com",
		ProbeResults: []evidence.ProbeResult{
			{ProbeName: "DNS", Layer: evidence.LayerDNS, Result: evidence.ResultOK},
			{ProbeName: "TLS", Layer: evidence.LayerTLS, Result: evidence.ResultFailed, ErrorMessage: "reset before certificate"},
		},
		Assessment: evidence.Assessment{Level: evidence.AssessmentSuspiciousHigh, Category: "TLS_SNI_INTERRUPTION_PATTERN", Summary: "TLS interrupted"},
	}
	if err := WriteDiagnoseHuman(&b, result); err != nil {
		t.Fatalf("WriteDiagnoseHuman returned error: %v", err)
	}
	out := b.String()
	if !strings.Contains(out, "Layer summary") {
		t.Fatalf("missing layer summary: %q", out)
	}
	if !strings.Contains(out, "TLS_SNI_INTERRUPTION_PATTERN") {
		t.Fatalf("missing assessment: %q", out)
	}
}

func TestWriteDiagnoseJSONIncludesAssessment(t *testing.T) {
	var b strings.Builder
	result := diagnose.Result{Target: "https://example.com", Assessment: evidence.Assessment{Level: evidence.AssessmentUnknown, Category: "INSUFFICIENT_EVIDENCE"}}
	if err := WriteDiagnoseJSON(&b, result); err != nil {
		t.Fatalf("WriteDiagnoseJSON returned error: %v", err)
	}
	if !strings.Contains(b.String(), "INSUFFICIENT_EVIDENCE") {
		t.Fatalf("missing assessment JSON: %q", b.String())
	}
}
```

Add imports:

```go
"icurl/internal/diagnose"
"icurl/internal/evidence"
```

- [ ] **Step 2: Run report tests and verify failure**

Run:

```bash
go test ./internal/report -run Diagnose -v
```

Expected: FAIL because diagnostic report functions are missing.

- [ ] **Step 3: Implement diagnostic human report**

Append to `internal/report/human.go`:

```go
func WriteDiagnoseHuman(w io.Writer, result diagnose.Result) error {
	if _, err := fmt.Fprintf(w, "Target: %s\n\n", result.Target); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Layer summary:"); err != nil {
		return err
	}
	for _, probeResult := range result.ProbeResults {
		if _, err := fmt.Fprintf(w, "  %-5s %-8s %s\n", probeResult.Layer, probeResult.Result, probeResult.ErrorMessage); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Assessment:\n  %s %s\n  %s\n", result.Assessment.Level, result.Assessment.Category, result.Assessment.Summary); err != nil {
		return err
	}
	if len(result.Assessment.Reasons) > 0 {
		if _, err := fmt.Fprintln(w, "\nReasons:"); err != nil {
			return err
		}
		for _, reason := range result.Assessment.Reasons {
			if _, err := fmt.Fprintf(w, "  - %s\n", reason); err != nil {
				return err
			}
		}
	}
	if len(result.Assessment.NextSteps) > 0 {
		if _, err := fmt.Fprintln(w, "\nNext steps:"); err != nil {
			return err
		}
		for _, step := range result.Assessment.NextSteps {
			if _, err := fmt.Fprintf(w, "  - %s\n", step); err != nil {
				return err
			}
		}
	}
	if result.CapturePath != "" {
		_, err := fmt.Fprintf(w, "\nPacket capture: %s\n", result.CapturePath)
		return err
	}
	return nil
}
```

Add import to `human.go`:

```go
"icurl/internal/diagnose"
```

- [ ] **Step 4: Implement diagnostic JSON report**

Append to `internal/report/json.go`:

```go
func WriteDiagnoseJSON(w io.Writer, result diagnose.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
```

Add import to `json.go`:

```go
"icurl/internal/diagnose"
```

- [ ] **Step 5: Wire diagnostic reports into CLI**

In `internal/cli/app.go`, replace temporary output in `runDiagnose`:

```go
if jsonOut {
	fmt.Fprintf(stdout, "%+v\n", result)
	return 0
}
fmt.Fprintf(stdout, "Assessment: %s %s\n", result.Assessment.Level, result.Assessment.Category)
return 0
```

With:

```go
if jsonOut {
	if err := report.WriteDiagnoseJSON(stdout, result); err != nil {
		fmt.Fprintf(stderr, "icurl: %v\n", err)
		return 1
	}
	return 0
}
if err := report.WriteDiagnoseHuman(stdout, result); err != nil {
	fmt.Fprintf(stderr, "icurl: %v\n", err)
	return 1
}
return 0
```

- [ ] **Step 6: Run tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/report/human.go internal/report/json.go internal/report/report_test.go internal/cli/app.go
git commit -m "Add diagnostic report renderers"
```

## Task 11: Add macOS Deep Diagnose Capture Orchestration

**Files:**
- Create: `internal/platform/macos/capture.go`
- Create: `internal/platform/macos/capture_test.go`
- Modify: `internal/diagnose/engine.go`
- Modify: `internal/diagnose/engine_test.go`
- Modify: `cmd/icurl/main.go`

- [ ] **Step 1: Write packet capture command test**

Create `internal/platform/macos/capture_test.go`:

```go
package macos

import (
	"context"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	commands []string
}

func (f *fakeCommandRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	f.commands = append(f.commands, name+" "+strings.Join(args, " "))
	return fakeProcess{}, nil
}

type fakeProcess struct{}

func (fakeProcess) Stop() error { return nil }

func TestCaptureUsesSudoTcpdumpAndPcapPath(t *testing.T) {
	runner := &fakeCommandRunner{}
	capture := Capture{Runner: runner, OutputDir: t.TempDir()}
	path, stop, err := capture.Start(context.Background())
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop returned error: %v", err)
	}
	if !strings.HasSuffix(path, ".pcap") {
		t.Fatalf("expected pcap path, got %q", path)
	}
	if len(runner.commands) != 1 || !strings.Contains(runner.commands[0], "sudo /usr/sbin/tcpdump") {
		t.Fatalf("unexpected commands: %#v", runner.commands)
	}
}
```

- [ ] **Step 2: Implement macOS capture orchestration**

Create `internal/platform/macos/capture.go`:

```go
package macos

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Process interface {
	Stop() error
}

type CommandRunner interface {
	Start(context.Context, string, ...string) (Process, error)
}

type execRunner struct{}

type execProcess struct {
	cmd *exec.Cmd
}

func (execRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd: cmd}, nil
}

func (p execProcess) Stop() error {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(os.Interrupt)
	}
	return p.cmd.Wait()
}

type Capture struct {
	Runner    CommandRunner
	OutputDir string
}

func (c Capture) Start(ctx context.Context) (string, func() error, error) {
	runner := c.Runner
	if runner == nil {
		runner = execRunner{}
	}
	outputDir := c.OutputDir
	if outputDir == "" {
		outputDir = "."
	}
	path := filepath.Join(outputDir, fmt.Sprintf("icurl-trace-%s.pcap", time.Now().Format("20060102-150405")))
	process, err := runner.Start(ctx, "sudo", "/usr/sbin/tcpdump", "-i", "any", "-s", "0", "-w", path)
	if err != nil {
		return "", nil, err
	}
	return path, process.Stop, nil
}
```

- [ ] **Step 3: Add capture hook to diagnostic engine**

Modify `internal/diagnose/engine.go`.

Add:

```go
type PacketCapture interface {
	Start(context.Context) (string, func() error, error)
}
```

Change `Engine` to:

```go
type Engine struct {
	Probes  []probe.Probe
	Capture PacketCapture
}
```

At the start of `Run`, before running probes:

```go
var capturePath string
var stopCapture func() error
if cfg.Deep && e.Capture != nil {
	path, stop, err := e.Capture.Start(ctx)
	if err == nil {
		capturePath = path
		stopCapture = stop
	}
}
if stopCapture != nil {
	defer stopCapture()
}
```

Return `CapturePath: capturePath` in the result.

- [ ] **Step 4: Add deep diagnose engine test**

Append to `internal/diagnose/engine_test.go`:

```go
type fakeCapture struct {
	started bool
}

func (f *fakeCapture) Start(ctx context.Context) (string, func() error, error) {
	f.started = true
	return "trace.pcap", func() error { return nil }, nil
}

func TestEngineStartsCaptureForDeepDiagnostics(t *testing.T) {
	u, _ := url.Parse("https://example.com")
	capture := &fakeCapture{}
	engine := Engine{Capture: capture}

	result := engine.Run(context.Background(), Config{URL: u, Deep: true})
	if !capture.started {
		t.Fatal("expected capture to start")
	}
	if result.CapturePath != "trace.pcap" {
		t.Fatalf("unexpected capture path %q", result.CapturePath)
	}
}
```

- [ ] **Step 5: Wire capture in main**

Modify `cmd/icurl/main.go` to import:

```go
"icurl/internal/platform/macos"
```

Change engine construction to:

```go
engine := diagnose.Engine{
	Probes: []probe.Probe{
		dnsprobe.Probe{},
		tcpprobe.Probe{},
		tlsprobe.Probe{},
		httpprobe.Probe{Runner: runner},
		quicprobe.Probe{Runner: runner},
	},
	Capture: macos.Capture{},
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
go test ./...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/platform/macos/capture.go internal/platform/macos/capture_test.go internal/diagnose/engine.go internal/diagnose/engine_test.go cmd/icurl/main.go
git commit -m "Add macOS deep diagnose capture"
```

## Task 12: Add README, Local Smoke Tests, and Final Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write README usage content**

Replace `README.md` with:

```markdown
# icurl

`icurl` is a diagnostics-first curl-like CLI for HTTP and HTTPS. It supports common request workflows and can explain failures across DNS, TCP, TLS, HTTP, UDP, and QUIC layers.

## Scope

The first version is curl-like, not a full curl clone. It focuses on HTTP/HTTPS, HTTP/1.1, HTTP/2, HTTP/3, and network diagnostics.

It does not provide proxy, VPN, tunnel, or censorship-circumvention functionality.

## Examples

```bash
icurl https://example.com
icurl -I https://example.com
icurl -i https://example.com
icurl -X POST -H 'Content-Type: application/json' -d '{}' https://example.com
icurl --http2 https://example.com
icurl --http3 https://example.com
icurl --http3-only https://example.com
icurl diagnose https://example.com
icurl diagnose --json https://example.com
icurl diagnose --deep https://example.com
```

## Deep diagnostics

`icurl diagnose --deep` uses `sudo /usr/sbin/tcpdump` on macOS to capture a short packet trace while probes run. Packet captures can contain sensitive data, so they are saved locally and never uploaded by `icurl`.

## Development

```bash
go test ./...
go build ./cmd/icurl
```
```

- [ ] **Step 2: Run full automated verification**

Run:

```bash
go test ./...
go build ./cmd/icurl
```

Expected: PASS.

- [ ] **Step 3: Run local CLI smoke tests**

Run:

```bash
./icurl https://example.com
./icurl -I https://example.com
./icurl --json https://example.com
./icurl diagnose https://example.com
```

Expected: commands exit 0 in a normal network environment. If a real network command fails, keep the failure output and confirm that `go test ./...` still passes, because real network smoke tests are not deterministic.

- [ ] **Step 4: Check repository state**

Run:

```bash
git status --short
git diff --check
```

Expected: only intended README and source changes are present; no whitespace errors.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "Document icurl usage"
```

## Final Self-Review Checklist

After Task 12, verify:

- `go test ./...` passes.
- `go build ./cmd/icurl` passes.
- CLI handles no-argument usage.
- CLI handles basic GET, HEAD, POST flags.
- HTTP/1.1 and HTTP/2 paths work through `net/http`.
- HTTP/3 path is wired through `quic-go/http3`.
- `diagnose` runs DNS, TCP, TLS, HTTP, and QUIC probes.
- Classifier returns confidence-based assessments.
- Human report includes layer summary and next steps.
- JSON report includes probe results and assessment.
- `diagnose --deep` starts macOS tcpdump only when explicitly requested.
- Packet capture output is local and no upload path exists.
- README states curl-like scope and non-circumvention boundary.

## Plan Self-Review

Spec coverage:

- Common request flags are covered in Tasks 2 through 4.
- HTTP/1.1 and HTTP/2 are covered in Task 3.
- HTTP/3 is covered in Task 5.
- Evidence and classification are covered in Task 6.
- DNS, TCP, TLS, HTTP, and QUIC probes are covered in Tasks 7 and 8.
- Diagnostic orchestration is covered in Task 9.
- Human and JSON diagnostic reports are covered in Task 10.
- macOS deep diagnose is covered in Task 11.
- README and smoke verification are covered in Task 12.

Placeholder scan:

- This plan contains no `TBD`, `TODO`, or placeholder target names.

Type consistency:

- CLI uses `request.Config`, `request.Result`, and dependency interfaces consistently.
- Probes all return `evidence.ProbeResult` through `probe.Probe`.
- Diagnostic engine returns `diagnose.Result` and report functions consume that type.
- Classifier consumes `[]evidence.ProbeResult` and returns `evidence.Assessment`.
