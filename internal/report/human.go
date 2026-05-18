package report

import (
	"fmt"
	"io"
	"sort"

	"icurl/internal/diagnose"
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

	if result.Body != nil {
		_, err := io.Copy(w, result.Body)
		_ = result.Body.Close()
		return err
	}
	return nil
}

func WriteDiagnoseHuman(w io.Writer, result diagnose.Result) error {
	if _, err := fmt.Fprintf(w, "Target: %s\n\n", result.Target); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Layer summary:"); err != nil {
		return err
	}
	for _, probe := range result.ProbeResults {
		if _, err := fmt.Fprintf(w, "  %-5s %-8s %s\n", probe.Layer, probe.Result, probe.ErrorMessage); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "Assessment:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Level: %s\n", result.Assessment.Level); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Category: %s\n", result.Assessment.Category); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  Summary: %s\n", result.Assessment.Summary); err != nil {
		return err
	}
	if len(result.Assessment.Reasons) > 0 {
		if _, err := fmt.Fprintln(w, "Reasons:"); err != nil {
			return err
		}
		for _, reason := range result.Assessment.Reasons {
			if _, err := fmt.Fprintf(w, "  - %s\n", reason); err != nil {
				return err
			}
		}
	}
	if len(result.Assessment.NextSteps) > 0 {
		if _, err := fmt.Fprintln(w, "Next steps:"); err != nil {
			return err
		}
		for _, step := range result.Assessment.NextSteps {
			if _, err := fmt.Fprintf(w, "  - %s\n", step); err != nil {
				return err
			}
		}
	}
	if result.CapturePath != "" {
		if _, err := fmt.Fprintf(w, "Packet capture: %s\n", result.CapturePath); err != nil {
			return err
		}
	}
	return nil
}
