package cli

import (
	"context"
	"fmt"
	"io"
)

type Dependencies struct{}

func Run(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, deps Dependencies) int {
	_ = ctx
	_ = stdout
	_ = deps

	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: icurl [options] URL")
		fmt.Fprintln(stderr, "       icurl diagnose [options] URL")
		return 2
	}

	fmt.Fprintln(stderr, "icurl: request execution is not wired yet")
	return 2
}
