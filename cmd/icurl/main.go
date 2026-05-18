package main

import (
	"context"
	"os"

	"icurl/internal/cli"
	"icurl/internal/request"
)

func main() {
	code := cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{Requester: request.NewRunner()})
	os.Exit(code)
}
