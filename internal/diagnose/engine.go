package diagnose

import (
	"context"
	"net"
	"net/url"
	"sync"

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

type PacketCapture interface {
	Start(context.Context) (string, func() error, error)
}

type Engine struct {
	Probes  []probe.Probe
	Capture PacketCapture
}

func (e Engine) Run(ctx context.Context, cfg Config) Result {
	if cfg.URL == nil {
		return Result{Assessment: evidence.Assessment{
			Level:    evidence.AssessmentUnknown,
			Category: "INSUFFICIENT_EVIDENCE",
			Summary:  "diagnostic URL is missing",
		}}
	}

	target := probe.Target{
		URL:  cfg.URL,
		Host: cfg.URL.Hostname(),
		Port: cfg.URL.Port(),
		IPs:  nil,
	}
	if target.Port == "" {
		target.Port = defaultPort(cfg.URL.Scheme)
	}

	// Unify DNS resolution at the engine level
	ips, err := net.LookupIP(target.Host)
	if err == nil && len(ips) > 0 {
		target.IPs = ips
	}

	capturePath := ""
	if cfg.Deep && e.Capture != nil {
		path, stopCapture, err := e.Capture.Start(ctx)
		if err == nil {
			capturePath = path
			defer func() {
				_ = stopCapture()
			}()
		}
	}

	results := make([]evidence.ProbeResult, 0, len(e.Probes))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range e.Probes {
		wg.Add(1)
		go func(pr probe.Probe) {
			defer wg.Done()
			res := pr.Run(ctx, target)
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	return Result{
		Target:       cfg.URL.String(),
		ProbeResults: results,
		Assessment:   classifier.Classify(results),
		CapturePath:  capturePath,
	}
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}
