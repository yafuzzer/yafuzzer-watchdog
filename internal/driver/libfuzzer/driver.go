// Package libfuzzer adapts a single libFuzzer process to the watchdog contracts.
package libfuzzer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

type Driver struct{ highWater map[string]float64 }

var _ watchdog.Driver = (*Driver)(nil)

func (d *Driver) Prepare(c watchdog.RunConfig) (watchdog.LaunchSpec, error) {
	c, err := c.Resolve()
	if err != nil {
		return watchdog.LaunchSpec{}, err
	}
	if c.Engine != "libfuzzer" {
		return watchdog.LaunchSpec{}, fmt.Errorf("libFuzzer driver cannot run engine %q", c.Engine)
	}
	dirs := []string{c.OutputDir, c.ArtifactsDir, c.RunsDir}
	if c.InputDir != "" {
		info, err := os.Stat(c.InputDir)
		if err != nil {
			return watchdog.LaunchSpec{}, fmt.Errorf("seed corpus: %w", err)
		}
		if !info.IsDir() {
			return watchdog.LaunchSpec{}, fmt.Errorf("seed corpus is not a directory: %s", c.InputDir)
		}
		dirs = append(dirs, c.InputDir)
	}
	for i, dir := range dirs {
		if info, err := os.Stat(dir); err == nil && !info.IsDir() {
			return watchdog.LaunchSpec{}, fmt.Errorf("not a directory: %s", dir)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return watchdog.LaunchSpec{}, fmt.Errorf("inspect directory %s: %w", dir, err)
		}
		for _, other := range dirs[:i] {
			if overlap(canonical(dir), canonical(other)) {
				return watchdog.LaunchSpec{}, fmt.Errorf("corpus, artifacts and run directories must not overlap: %s and %s", dir, other)
			}
		}
	}

	var extra []string
	finalStats := false
	for _, arg := range c.Command[1:] {
		name, value, ok := strings.Cut(arg, "=")
		if !ok || !strings.HasPrefix(name, "-") || strings.HasPrefix(name, "--") {
			return watchdog.LaunchSpec{}, fmt.Errorf("libFuzzer arguments must use -name=value; use --input/--output for corpora: %q", arg)
		}
		switch name {
		case "-artifact_prefix":
			path := value
			if !filepath.IsAbs(path) {
				path = filepath.Join(c.WorkDir, path)
			}
			if value == "" || canonical(path) != canonical(c.ArtifactsDir) {
				return watchdog.LaunchSpec{}, fmt.Errorf("-artifact_prefix conflicts with --artifacts; set the path through watchdog")
			}
			continue // Emit a single canonical value below.
		case "-exact_artifact_path":
			if value != "" {
				return watchdog.LaunchSpec{}, fmt.Errorf("-exact_artifact_path overrides --artifacts and is not supported")
			}
		case "-jobs", "-workers", "-fork", "-merge", "-merge_inner", "-minimize_crash", "-cleanse_crash", "-minimize_crash_internal_step", "-analyze_dict", "-help", "-collect_data_flow":
			n, err := strconv.Atoi(value)
			if err != nil || n != 0 {
				return watchdog.LaunchSpec{}, fmt.Errorf("%s is unsupported: this version runs one fuzzing process", arg)
			}
		case "-close_fd_mask":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 3 || n&2 != 0 {
				return watchdog.LaunchSpec{}, fmt.Errorf("%s disables stderr required for monitoring", arg)
			}
		case "-verbosity":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 {
				return watchdog.LaunchSpec{}, fmt.Errorf("%s disables statistics required for monitoring", arg)
			}
		case "-max_total_time", "-stale_corpus_timeout":
			return watchdog.LaunchSpec{}, fmt.Errorf("use watchdog --fuzzing-timeout or --no-progress-timeout instead of %s", name)
		case "-print_final_stats":
			finalStats = true
		}
		extra = append(extra, arg)
	}

	args := []string{c.OutputDir}
	if c.InputDir != "" {
		args = append(args, c.InputDir)
	}
	args = append(args, "-artifact_prefix="+c.ArtifactsDir+string(os.PathSeparator))
	if !finalStats {
		args = append(args, "-print_final_stats=1")
	}
	args = append(args, extra...)
	executable := c.Command[0]
	if strings.ContainsRune(executable, os.PathSeparator) && !filepath.IsAbs(executable) {
		executable = filepath.Join(c.WorkDir, executable)
	}
	d.highWater = make(map[string]float64)
	return watchdog.LaunchSpec{
		Executable:  executable,
		Args:        args,
		WorkDir:     c.WorkDir,
		Directories: []string{c.OutputDir, c.ArtifactsDir},
	}, nil
}

// Resolve existing ancestors too, so a symlink cannot hide overlapping paths.
func canonical(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	parent := filepath.Dir(path)
	if parent == path {
		return filepath.Clean(path)
	}
	return filepath.Join(canonical(parent), filepath.Base(path))
}

func overlap(a, b string) bool {
	inside := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
	}
	return inside(a, b) || inside(b, a)
}

func (*Driver) Interpret(exit watchdog.ExitStatus, evidence watchdog.AttemptEvidence) watchdog.AttemptOutcome {
	for _, kind := range []string{"out_of_memory", "timeout", "leak", "sanitizer", "crash"} {
		if evidence.Kinds[kind] {
			return watchdog.AttemptOutcome{Outcome: watchdog.OutcomeTargetError, ErrorKind: kind}
		}
	}
	switch exit.Signal {
	case "SIGSEGV", "SIGABRT", "SIGILL", "SIGFPE", "SIGBUS", "SIGTRAP":
		return watchdog.AttemptOutcome{Outcome: watchdog.OutcomeTargetError, ErrorKind: "crash"}
	}
	if evidence.Artifact && exit.Code != nil && *exit.Code != 0 {
		return watchdog.AttemptOutcome{Outcome: watchdog.OutcomeTargetError, ErrorKind: "crash"}
	}
	if exit.Signal != "" {
		return watchdog.AttemptOutcome{Outcome: watchdog.OutcomeSignaled}
	}
	if exit.Code == nil || *exit.Code != 0 {
		return watchdog.AttemptOutcome{Outcome: watchdog.OutcomeFailed}
	}
	return watchdog.AttemptOutcome{Outcome: watchdog.OutcomeCompleted}
}

func (*Driver) MetricRules() map[string]watchdog.MetricRule {
	return map[string]watchdog.MetricRule{
		"executions":                          watchdog.MetricSum,
		"execs_per_second":                    watchdog.MetricLast,
		"corpus_entries":                      watchdog.MetricLast,
		"corpus_bytes":                        watchdog.MetricLast,
		"rss_bytes":                           watchdog.MetricMax,
		"peak_rss_bytes":                      watchdog.MetricMax,
		"libfuzzer.coverage":                  watchdog.MetricMax,
		"libfuzzer.features":                  watchdog.MetricMax,
		"libfuzzer.new_units_added":           watchdog.MetricSum,
		"libfuzzer.slowest_unit_time_seconds": watchdog.MetricMax,
	}
}
