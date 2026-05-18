package report

import (
	"fmt"
	"io"
	"sort"

	"icurl/internal/request"
)

type RequestHumanOptions struct {
	IncludeHeaders bool
}

func WriteRequestHuman(w io.Writer, result request.Result, opts RequestHumanOptions) error {
	if opts.IncludeHeaders {
		if _, err := fmt.Fprintf(w, "%s %d\n", result.Protocol, result.StatusCode); err != nil {
			return err
		}

		names := make([]string, 0, len(result.ResponseHeaders))
		for name := range result.ResponseHeaders {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			for _, value := range result.ResponseHeaders.Values(name) {
				if _, err := fmt.Fprintf(w, "%s: %s\n", name, value); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	_, err := w.Write(result.Body)
	return err
}
