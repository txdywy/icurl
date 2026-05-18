package request

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type Runner struct {
	newHTTP3RoundTripper func(Config) (http.RoundTripper, func() error, error)
}

func NewRunner() *Runner {
	return &Runner{newHTTP3RoundTripper: defaultHTTP3RoundTripper}
}

func (r *Runner) Do(ctx context.Context, cfg Config) (Result, error) {
	if cfg.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.MaxTime)
		defer cancel()
	}

	if cfg.Protocol == ProtocolHTTP3 || cfg.Protocol == ProtocolHTTP3Only {
		return r.doHTTP3(ctx, cfg)
	}
	return r.doHTTP(ctx, cfg)
}

func (r *Runner) doHTTP(ctx context.Context, cfg Config) (Result, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: cfg.ConnectTimeout,
		}).DialContext,
		TLSHandshakeTimeout: cfg.ConnectTimeout,
		ForceAttemptHTTP2:   cfg.Protocol != ProtocolHTTP11,
	}
	if cfg.Protocol == ProtocolHTTP11 {
		transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	}
	defer transport.CloseIdleConnections()

	return execute(ctx, cfg, transport)
}

func (r *Runner) doHTTP3(ctx context.Context, cfg Config) (Result, error) {
	newHTTP3RoundTripper := r.newHTTP3RoundTripper
	if newHTTP3RoundTripper == nil {
		newHTTP3RoundTripper = defaultHTTP3RoundTripper
	}
	transport, closeTransport, err := newHTTP3RoundTripper(cfg)
	if err != nil {
		if cfg.Protocol == ProtocolHTTP3 {
			cfg.Protocol = ProtocolAuto
			return r.doHTTP(ctx, cfg)
		}
		return Result{}, err
	}
	defer closeTransport()

	result, err := execute(ctx, cfg, transport)
	if err != nil && cfg.Protocol == ProtocolHTTP3 {
		cfg.Protocol = ProtocolAuto
		return r.doHTTP(ctx, cfg)
	}
	return result, err
}

func defaultHTTP3RoundTripper(Config) (http.RoundTripper, func() error, error) {
	transport := &http3.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	return transport, transport.Close, nil
}

func execute(ctx context.Context, cfg Config, transport http.RoundTripper) (Result, error) {
	started := time.Now()
	var redirects []Redirect
	client := &http.Client{Transport: transport}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	method := cfg.EffectiveMethod()
	body := cfg.Body
	currentURL := cfg.URL
	var resp *http.Response
	for {
		req, err := http.NewRequestWithContext(ctx, method, currentURL, strings.NewReader(body))
		if err != nil {
			return Result{}, err
		}
		for key, values := range cfg.Headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		resp, err = client.Do(req)
		if err != nil {
			return Result{}, err
		}

		location := resp.Header.Get("Location")
		if !cfg.FollowRedirect || location == "" || (resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect) {
			break
		}
		if len(redirects) >= 10 {
			resp.Body.Close()
			return Result{}, fmt.Errorf("stopped after 10 redirects")
		}

		nextURL, err := resp.Request.URL.Parse(location)
		if err != nil {
			resp.Body.Close()
			return Result{}, err
		}
		redirects = append(redirects, Redirect{From: resp.Request.URL.String(), To: nextURL.String(), StatusCode: resp.StatusCode})
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		currentURL = nextURL.String()
		if resp.StatusCode == http.StatusSeeOther || ((resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) && method == http.MethodPost) {
			method = http.MethodGet
			body = ""
		}
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, err
	}

	return Result{
		URL:             resp.Request.URL.String(),
		StatusCode:      resp.StatusCode,
		Protocol:        resp.Proto,
		ResponseHeaders: resp.Header.Clone(),
		Body:            responseBody,
		Timing:          Timing{Total: time.Since(started)},
		Redirects:       redirects,
	}, nil
}
