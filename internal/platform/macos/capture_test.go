package macos

import (
	"context"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	command string
}

func (r *fakeCommandRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	_ = ctx
	r.command = strings.Join(append([]string{name}, args...), " ")
	return fakeProcess{}, nil
}

type fakeProcess struct{}

func (fakeProcess) Stop() error {
	return nil
}

func TestCaptureUsesSudoTcpdumpAndPcapPath(t *testing.T) {
	runner := &fakeCommandRunner{}
	capture := Capture{Runner: runner, OutputDir: t.TempDir()}

	path, stop, err := capture.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".pcap") {
		t.Fatalf("expected pcap path, got %q", path)
	}
	if err := stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if !strings.Contains(runner.command, "sudo /usr/sbin/tcpdump") {
		t.Fatalf("expected sudo tcpdump command, got %q", runner.command)
	}
}
