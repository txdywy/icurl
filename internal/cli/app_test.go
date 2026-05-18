package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunShowsUsageWithoutArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Run(context.Background(), []string{}, &stdout, &stderr, Dependencies{})

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "usage: icurl") {
		t.Fatalf("expected usage in stderr, got %q", stderr.String())
	}
}
