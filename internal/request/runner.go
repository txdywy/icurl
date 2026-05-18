package request

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Do(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Protocol == ProtocolHTTP3 || cfg.Protocol == ProtocolHTTP3Only {
		return Result{}, errors.New("HTTP/3 runner is not configured")
	}

	if cfg.MaxTime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.MaxTime)
		defer cancel()
	}

	started := time.Now()
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

	var redirects []Redirect
	client := &http.Client{Transport: transport}
	if !cfg.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			previous := via[len(via)-1]
			redirects = append(redirects, Redirect{URL: previous.URL.String()})
			return nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, cfg.EffectiveMethod(), cfg.URL, strings.NewReader(cfg.Body))
	if err != nil {
		return Result{}, err
	}
	for key, values := range cfg.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, err
	}

	return Result{
		URL:             resp.Request.URL.String(),
		StatusCode:      resp.StatusCode,
		Protocol:        resp.Proto,
		ResponseHeaders: resp.Header.Clone(),
		Body:            body,
		Timing:          Timing{Total: time.Since(started)},
		Redirects:       redirects,
	}, nil
}
