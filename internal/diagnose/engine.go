package diagnose

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync"

	"icurl/internal/classifier"
	"icurl/internal/evidence"
	"icurl/internal/probe"
	dnsprobe "icurl/internal/probe/dns"
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

	results := make([]evidence.ProbeResult, len(e.Probes))

	dnsIndex := -1
	var dnsProbe probe.Probe
	for i, p := range e.Probes {
		if _, ok := p.(dnsprobe.Probe); ok {
			dnsIndex = i
			dnsProbe = p
			break
		}
	}

	if dnsProbe != nil {
		results[dnsIndex] = dnsProbe.Run(ctx, target)
		if results[dnsIndex].Result == evidence.ResultOK {
			var targetIPs []net.IP
			for _, obs := range results[dnsIndex].Observations {
				if strings.HasPrefix(obs, "resolved ") {
					ipStr := strings.TrimPrefix(obs, "resolved ")
					if ip := net.ParseIP(ipStr); ip != nil {
						targetIPs = append(targetIPs, ip)
					}
				}
			}
			target.IPs = targetIPs
		}
	} else {
		// Fallback pre-lookup using DefaultResolver if DNS probe is not in list
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", target.Host)
		if err == nil && len(ips) > 0 {
			target.IPs = ips
		}
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

	var wg sync.WaitGroup

	for i, p := range e.Probes {
		if i == dnsIndex {
			continue
		}
		wg.Add(1)
		go func(index int, pr probe.Probe) {
			defer wg.Done()
			results[index] = pr.Run(ctx, target)
		}(i, p)
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
