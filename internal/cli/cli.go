// Package cli converts command-line arguments to a watchdog configuration.
package cli

import (
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func Parse(args []string, output io.Writer) (watchdog.RunConfig, error) {
	c := watchdog.DefaultConfig()
	flags := flag.NewFlagSet("yafwd", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&c.Engine, "engine", c.Engine, "required fuzzing engine (libfuzzer)")
	flags.StringVar(&c.Engine, "e", c.Engine, "alias for --engine")
	flags.StringVar(&c.InputDir, "input", "", "optional seed corpus directory")
	flags.StringVar(&c.InputDir, "i", "", "alias for --input")
	flags.StringVar(&c.OutputDir, "output", c.OutputDir, "generated corpus directory")
	flags.StringVar(&c.OutputDir, "o", c.OutputDir, "alias for --output")
	flags.StringVar(&c.ArtifactsDir, "artifacts", c.ArtifactsDir, "fuzzing artifacts directory")
	flags.StringVar(&c.ArtifactsDir, "a", c.ArtifactsDir, "alias for --artifacts")
	flags.StringVar(&c.RunsDir, "runs-dir", c.RunsDir, "parent directory for run records")
	flags.StringVar((*string)(&c.Restart), "restart", string(c.Restart), "restart mode: never or on-crash")
	flags.Func("fuzzing-timeout", "total active fuzzing time; seconds or duration (0 disables)", durationFlag(&c.FuzzingTimeout))
	flags.Func("no-progress-timeout", "active time without new coverage; seconds or duration (0 disables)", durationFlag(&c.NoProgressTimeout))
	flags.Func("shutdown-timeout", "grace period before forceful termination (default 5s)", durationFlag(&c.ShutdownTimeout))
	flags.Usage = func() {
		fmt.Fprintln(output, "Usage: yafwd [OPTIONS] -- FUZZING_COMMAND [ARGS...]")
		fmt.Fprintln(output, "\nRun a fuzzing session and save its journal, metrics and result.")
		fmt.Fprintln(output, "\nOptions:")
		flags.PrintDefaults()
	}

	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	watchdogArgs := args
	if separator >= 0 {
		watchdogArgs = args[:separator]
		c.Command = append([]string(nil), args[separator+1:]...)
	}
	if err := flags.Parse(watchdogArgs); err != nil {
		return c, err
	}
	if flags.NArg() > 0 {
		return c, fmt.Errorf("unexpected argument %q: put the fuzzing command after --", flags.Arg(0))
	}
	if separator < 0 {
		return c, fmt.Errorf("separate watchdog options from the fuzzing command with --")
	}
	c.Engine = strings.ToLower(c.Engine)
	if c.Engine == "" {
		return c, fmt.Errorf("--engine is required")
	}
	if c.Engine != "libfuzzer" {
		return c, fmt.Errorf("unsupported engine %q: only libfuzzer is available", c.Engine)
	}
	return c.Resolve()
}

var bareSeconds = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)$`)

func durationFlag(target *time.Duration) func(string) error {
	return func(value string) error {
		if bareSeconds.MatchString(value) {
			value += "s"
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*target = parsed
		return nil
	}
}
