package diagnose

import (
	"context"
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
	target := probe.Target{
		URL:  cfg.URL,
		Host: cfg.URL.Hostname(),
		Port: cfg.URL.Port(),
		IPs:  nil,
	}
	if target.Port == "" {
		target.Port = defaultPort(cfg.URL.Scheme)
	}

	results := make([]evidence.ProbeResult, 0, len(e.Probes))
	for _, p := range e.Probes {
		results = append(results, p.Run(ctx, target))
	}

	return Result{
		Target:       cfg.URL.String(),
		ProbeResults: results,
		Assessment:   classifier.Classify(results),
	}
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}
