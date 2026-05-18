package main

import (
	"context"
	"os"

	"icurl/internal/cli"
	"icurl/internal/diagnose"
	"icurl/internal/probe"
	dnsprobe "icurl/internal/probe/dns"
	httpprobe "icurl/internal/probe/http"
	quicprobe "icurl/internal/probe/quic"
	tcpprobe "icurl/internal/probe/tcp"
	tlsprobe "icurl/internal/probe/tls"
	"icurl/internal/request"
)

func main() {
	runner := request.NewRunner()
	engine := diagnose.Engine{Probes: []probe.Probe{
		dnsprobe.Probe{},
		tcpprobe.Probe{},
		tlsprobe.Probe{},
		httpprobe.Probe{Runner: runner},
		quicprobe.Probe{Runner: runner},
	}}
	code := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{Requester: runner, Diagnoser: engine})
	os.Exit(code)
}
