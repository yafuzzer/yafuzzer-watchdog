//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/cli"
	"github.com/yafuzzer/yafuzzer-watchdog/internal/driver/libfuzzer"
	"github.com/yafuzzer/yafuzzer-watchdog/internal/storage"
	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func main() { os.Exit(mainCode()) }

func mainCode() int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		select {
		case sig := <-signals:
			cancel(&watchdog.SignalError{Signal: sig})
		case <-ctx.Done():
		}
	}()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	config, err := cli.Parse(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		diagnostic(stderr, err.Error())
		return 2
	}
	runner := watchdog.Runner{Driver: &libfuzzer.Driver{}, Store: &storage.FileStore{}}
	result, err := runner.Run(ctx, config)
	if result.Files.Directory != "" {
		diagnostic(stderr, "Session records: "+result.Files.Directory)
		if reportErr := report(stdout, result); reportErr != nil {
			diagnostic(stderr, "Write report: "+reportErr.Error())
			return 2
		}
	}
	if err != nil {
		diagnostic(stderr, err.Error())
		return 2
	}
	return exitCode(result)
}

func exitCode(result watchdog.RunResult) int {
	if result.Reason == watchdog.ReasonInterrupted {
		if result.StopSignal == "SIGINT" {
			return 130
		}
		return 143
	}
	if result.Reason == watchdog.ReasonFuzzingTimeout || result.Reason == watchdog.ReasonNoProgress {
		return 0
	}
	if result.Outcome != watchdog.OutcomeCompleted {
		return 1
	}
	return 0
}

func diagnostic(w io.Writer, message string) {
	for _, line := range strings.Split(strings.TrimSuffix(message, "\n"), "\n") {
		fmt.Fprintln(w, "[watchdog]", line)
	}
}
