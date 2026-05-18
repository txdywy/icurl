package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"icurl/internal/diagnose"
	"icurl/internal/report"
	"icurl/internal/request"
)

type Requester interface {
	Do(context.Context, request.Config) (request.Result, error)
}

type Diagnoser interface {
	Run(context.Context, diagnose.Config) diagnose.Result
}

type Dependencies struct {
	Requester Requester
	Diagnoser Diagnoser
}

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps Dependencies) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	if args[0] == "diagnose" {
		return runDiagnose(ctx, args[1:], stdout, stderr, deps)
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
	if cfg.JSON {
		err = report.WriteRequestJSON(stdout, result)
	} else {
		err = report.WriteRequestHuman(stdout, result, report.RequestHumanOptions{IncludeHeaders: cfg.IncludeHeaders})
	}
	if err != nil {
		fmt.Fprintf(stderr, "icurl: %v\n", err)
		return 1
	}
	return 0
}

func runDiagnose(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps Dependencies) int {
	fs := flag.NewFlagSet("icurl diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var deep bool
	var jsonOutput bool
	fs.BoolVar(&deep, "deep", false, "run deep diagnostics")
	fs.BoolVar(&jsonOutput, "json", false, "write JSON output")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "icurl: %v\n", err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "icurl: expected exactly one URL")
		return 2
	}

	parsed, err := url.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "icurl: invalid URL: %v\n", err)
		return 2
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		fmt.Fprintln(stderr, "icurl: invalid URL: expected http or https URL with host")
		return 2
	}
	if deps.Diagnoser == nil {
		fmt.Fprintln(stderr, "icurl: diagnoser dependency is not configured")
		return 2
	}

	result := deps.Diagnoser.Run(ctx, diagnose.Config{URL: parsed, Deep: deep})
	if jsonOutput {
		fmt.Fprintf(stdout, "%+v\n", result)
	} else {
		fmt.Fprintf(stdout, "Assessment: %s %s\n", result.Assessment.Level, result.Assessment.Category)
	}
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
