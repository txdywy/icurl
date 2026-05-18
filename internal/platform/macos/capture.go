package macos

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Process interface {
	Stop() error
}

type CommandRunner interface {
	Start(context.Context, string, ...string) (Process, error)
}

type execRunner struct{}

func (execRunner) Start(ctx context.Context, name string, args ...string) (Process, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProcess{cmd: cmd}, nil
}

type execProcess struct {
	cmd *exec.Cmd
}

func (p execProcess) Stop() error {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(os.Interrupt)
	}
	return p.cmd.Wait()
}

type Capture struct {
	Runner    CommandRunner
	OutputDir string
}

func (c Capture) Start(ctx context.Context) (string, func() error, error) {
	runner := c.Runner
	if runner == nil {
		runner = execRunner{}
	}
	outputDir := c.OutputDir
	if outputDir == "" {
		outputDir = "."
	}
	path := filepath.Join(outputDir, "icurl-trace-"+time.Now().Format("20060102-150405.000000000")+".pcap")
	process, err := runner.Start(ctx, "sudo", "/usr/sbin/tcpdump", "-i", "any", "-s", "0", "-w", path)
	if err != nil {
		return "", nil, err
	}
	return path, process.Stop, nil
}
