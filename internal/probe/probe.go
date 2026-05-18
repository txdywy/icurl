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
