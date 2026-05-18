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
