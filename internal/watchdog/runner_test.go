//go:build linux

package watchdog_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/driver/libfuzzer"
	"github.com/yafuzzer/yafuzzer-watchdog/internal/storage"
	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

// Use the test executable as a real child process, without requiring a compiler,
// shell or libFuzzer installation for the runtime tests.
func TestFuzzerProcess(t *testing.T) {
	if os.Getenv("YAFWD_TEST_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	writeReady := func() {
		if err := os.WriteFile(os.Getenv("YAFWD_TEST_READY"), []byte("ready"), 0o600); err != nil {
			panic(err)
		}
	}
	loop := func() {
		for {
			time.Sleep(time.Hour)
		}
	}
	switch mode {
	case "complete":
		fmt.Fprint(os.Stdout, "target output without newline")
		fmt.Fprintln(os.Stderr, "#2 INITED cov: 3 ft: 4 corp: 1/1b")
		fmt.Fprintln(os.Stderr, "#10 NEW cov: 4 ft: 5 corp: 2/2b")
		fmt.Fprint(os.Stderr, "#20 DONE cov: 4 ft: 5")
	case "failure":
		os.Exit(23)
	case "flaky", "repeat":
		counterPath := filepath.Join(os.Getenv("YAFWD_TEST_WORKDIR"), "attempt.count")
		data, _ := os.ReadFile(counterPath)
		count, _ := strconv.Atoi(string(data))
		count++
		if err := os.WriteFile(counterPath, []byte(strconv.Itoa(count)), 0o600); err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stderr, "#2 INITED cov: 2 ft: 2 corp: 1/4b rss: 20Mb")
		fmt.Fprintln(os.Stderr, "#10 NEW cov: 3 ft: 3 corp: 2/6b rss: 24Mb")
		time.Sleep(40 * time.Millisecond)
		fmt.Fprintln(os.Stderr, "stat::number_of_executed_units: 10")
		if mode == "repeat" || count < 3 {
			diagnostic := "ERROR: libFuzzer: deadly signal"
			switch os.Getenv("YAFWD_TEST_ERROR_KIND") {
			case "timeout":
				diagnostic = "ERROR: libFuzzer: timeout after 1 second"
			case "out_of_memory":
				diagnostic = "ERROR: libFuzzer: out-of-memory"
			case "sanitizer":
				diagnostic = "ERROR: AddressSanitizer: heap-buffer-overflow"
			}
			fmt.Fprintln(os.Stderr, diagnostic)
			fmt.Fprintln(os.Stderr, diagnostic)
			fmt.Fprintln(os.Stderr, "Test unit written to artifacts/crash-example")
			os.Exit(77)
		}
	case "finding":
		fmt.Fprintln(os.Stderr, "==42== ERROR: libFuzzer: deadly signal")
		fmt.Fprintln(os.Stderr, "Test unit written to artifacts/crash-example")
		os.Exit(77)
	case "silent":
		writeReady()
		loop()
	case "stream":
		fmt.Fprintln(os.Stdout, "target is running")
		fmt.Fprintln(os.Stderr, "#2 INITED cov: 2 ft: 2")
		loop()
	case "ignore":
		signal.Ignore(syscall.SIGTERM)
		writeReady()
		loop()
	case "tail":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM)
		writeReady()
		<-signals
		fmt.Fprint(os.Stderr, "#99 DONE cov: 8 ft: 12")
	case "progress", "reduce":
		fmt.Fprintln(os.Stderr, "#2 INITED cov: 2 ft: 2 corp: 1/4b")
		for i := 1; i <= 5; i++ {
			time.Sleep(100 * time.Millisecond)
			if mode == "progress" {
				fmt.Fprintf(os.Stderr, "#%d NEW cov: %d ft: %d\n", 10*i, 2+i, 2+i)
			} else {
				fmt.Fprintf(os.Stderr, "#%d REDUCE cov: 2 ft: 2 corp: 1/1b\n", 10*i)
			}
		}
	case "tree", "orphan":
		signal.Ignore(syscall.SIGTERM)
		exe, _ := os.Executable()
		child := exec.Command(exe, "-test.run=^TestFuzzerProcess$", "--", "child")
		child.Env = os.Environ()
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			panic(err)
		}
		for {
			if _, err := os.Stat(os.Getenv("YAFWD_TEST_CHILD_PID")); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		writeReady()
		if mode == "tree" {
			loop()
		}
	case "child":
		signal.Ignore(syscall.SIGTERM)
		if err := os.WriteFile(os.Getenv("YAFWD_TEST_CHILD_PID"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			panic(err)
		}
		loop()
	case "long-output":
		fmt.Fprintln(os.Stderr, strings.Repeat("x", 2*1024*1024))
		fmt.Fprint(os.Stderr, "#100 DONE cov: 1 ft: 1")
	default:
		panic("unknown helper mode: " + mode)
	}
	os.Exit(0)
}

type fixtureDriver struct {
	libfuzzer.Driver
	mode         string
	executable   string
	monitorError bool
	drainDelay   time.Duration
	errorKind    string
}

func (d *fixtureDriver) Prepare(c watchdog.RunConfig) (watchdog.LaunchSpec, error) {
	d.Driver = libfuzzer.Driver{}
	exe, err := os.Executable()
	if err != nil {
		return watchdog.LaunchSpec{}, err
	}
	if d.executable != "" {
		exe = d.executable
	}
	return watchdog.LaunchSpec{
		Executable: exe,
		Args:       []string{"-test.run=^TestFuzzerProcess$", "--", d.mode},
		WorkDir:    c.WorkDir,
		Env: []string{
			"YAFWD_TEST_HELPER=1",
			"YAFWD_TEST_WORKDIR=" + c.WorkDir,
			"YAFWD_TEST_ERROR_KIND=" + d.errorKind,
			"GORACE=atexit_sleep_ms=0",
			"YAFWD_TEST_READY=" + filepath.Join(c.WorkDir, "ready"),
			"YAFWD_TEST_CHILD_PID=" + filepath.Join(c.WorkDir, "child.pid"),
		},
		Directories: []string{c.OutputDir, c.ArtifactsDir},
	}, nil
}

func (d *fixtureDriver) Observe(ctx context.Context, src watchdog.Sources, emit func(watchdog.Observation) error) error {
	if d.monitorError {
		return errors.New("monitor unavailable")
	}
	err := d.Driver.Observe(ctx, src, emit)
	if d.drainDelay > 0 {
		time.Sleep(d.drainDelay)
	}
	return err
}

func runConfig(t *testing.T) watchdog.RunConfig {
	t.Helper()
	c := watchdog.DefaultConfig()
	c.Engine = "libfuzzer"
	c.WorkDir = t.TempDir()
	c.Command = []string{"fixture"}
	c.ShutdownTimeout = 50 * time.Millisecond
	return c
}

func run(t *testing.T, c watchdog.RunConfig, driver watchdog.Driver, store watchdog.Store) (watchdog.RunResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return (watchdog.Runner{Driver: driver, Store: store}).Run(ctx, c)
}

func TestRunnerSavesCompleteRunAndDrainsTail(t *testing.T) {
	result, err := run(t, runConfig(t), &fixtureDriver{mode: "complete"}, &storage.FileStore{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != watchdog.ReasonProcessExited || result.Outcome != watchdog.OutcomeCompleted || result.Exit.Code == nil || *result.Exit.Code != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	journal, _ := os.ReadFile(result.Files.Log)
	if !strings.Contains(string(journal), "target output without newline") || !strings.Contains(string(journal), "#20 DONE cov: 4 ft: 5") {
		t.Fatalf("incomplete log: %q", journal)
	}
	metrics, err := os.ReadFile(result.Files.Metrics)
	if err != nil || len(strings.Split(strings.TrimSpace(string(metrics)), "\n")) != 3 {
		t.Fatalf("incomplete metrics: %s (%v)", metrics, err)
	}
	for _, path := range []string{result.Files.Config, result.Files.Result} {
		data, err := os.ReadFile(path)
		if err != nil || !json.Valid(data) {
			t.Fatalf("invalid record %s: %v", path, err)
		}
	}
}

func TestRunnerDistinguishesExitAndFinding(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		code    int
		outcome watchdog.Outcome
	}{
		{"failure", 23, watchdog.OutcomeFailed},
		{"finding", 77, watchdog.OutcomeTargetError},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			result, err := run(t, runConfig(t), &fixtureDriver{mode: tc.mode}, &storage.FileStore{})
			if err != nil || result.Outcome != tc.outcome || result.Exit.Code == nil || *result.Exit.Code != tc.code {
				t.Fatalf("result=%#v, error=%v", result, err)
			}
		})
	}
}

func TestSilentProcessStillReachesLimits(t *testing.T) {
	for _, reason := range []watchdog.StopReason{watchdog.ReasonFuzzingTimeout, watchdog.ReasonNoProgress} {
		t.Run(string(reason), func(t *testing.T) {
			c := runConfig(t)
			if reason == watchdog.ReasonFuzzingTimeout {
				c.FuzzingTimeout = 150 * time.Millisecond
			} else {
				c.NoProgressTimeout = 150 * time.Millisecond
			}
			result, err := run(t, c, &fixtureDriver{mode: "silent"}, &storage.FileStore{})
			if err != nil || result.Reason != reason {
				t.Fatalf("result=%#v, error=%v", result, err)
			}
			if result.Outcome != watchdog.OutcomeStopped {
				t.Fatalf("planned shutdown classified as %s", result.Outcome)
			}
		})
	}
}

func TestOnlyCoverageExtendsNoProgressDeadline(t *testing.T) {
	for _, mode := range []string{"progress", "reduce"} {
		t.Run(mode, func(t *testing.T) {
			c := runConfig(t)
			c.NoProgressTimeout = 300 * time.Millisecond
			c.FuzzingTimeout = 3 * time.Second
			result, err := run(t, c, &fixtureDriver{mode: mode}, &storage.FileStore{})
			if err != nil {
				t.Fatal(err)
			}
			want := watchdog.ReasonProcessExited
			if mode == "reduce" {
				want = watchdog.ReasonNoProgress
			}
			if result.Reason != want {
				t.Fatalf("got %s, want %s", result.Reason, want)
			}
		})
	}
}

func TestSignalShutdownCapturesFinalOutput(t *testing.T) {
	c := runConfig(t)
	c.ShutdownTimeout = 500 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	done := make(chan struct{})
	var result watchdog.RunResult
	var err error
	go func() {
		result, err = (watchdog.Runner{Driver: &fixtureDriver{mode: "tail"}, Store: &storage.FileStore{}}).Run(ctx, c)
		close(done)
	}()
	waitForFile(t, filepath.Join(c.WorkDir, "ready"))
	cancel(&watchdog.SignalError{Signal: syscall.SIGTERM})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung")
	}
	if err != nil || result.Reason != watchdog.ReasonInterrupted || result.StopSignal != "SIGTERM" || result.Forced || result.Statistics.Metrics["executions"] != 99 {
		t.Fatalf("result=%#v, error=%v", result, err)
	}
}

func TestProcessGroupIsKilledIncludingOrphans(t *testing.T) {
	for _, mode := range []string{"tree", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			c := runConfig(t)
			c.FuzzingTimeout = 300 * time.Millisecond
			result, err := run(t, c, &fixtureDriver{mode: mode}, &storage.FileStore{})
			if err != nil || !result.Forced {
				t.Fatalf("result=%#v, error=%v", result, err)
			}
			data, err := os.ReadFile(filepath.Join(c.WorkDir, "child.pid"))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
			deadline := time.Now().Add(time.Second)
			for processRunning(pid) && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if processRunning(pid) {
				t.Fatal("descendant is still running")
			}
			want := watchdog.ReasonFuzzingTimeout
			if mode == "orphan" {
				want = watchdog.ReasonProcessExited
			}
			if result.Reason != want {
				t.Fatalf("got %s, want %s", result.Reason, want)
			}
		})
	}
}

type failingStore struct {
	watchdog.Store
	phase string
}

func (s failingStore) Log(message string) error {
	if s.phase == "log" {
		return errors.New("journal unavailable")
	}
	return s.Store.Log(message)
}

func (s failingStore) Begin(c watchdog.RunConfig, spec watchdog.LaunchSpec, at time.Time) (watchdog.RunFiles, error) {
	if s.phase == "begin" {
		return watchdog.RunFiles{}, errors.New("disk unavailable")
	}
	return s.Store.Begin(c, spec, at)
}

func (s failingStore) WriteOutput(stream watchdog.Stream, data []byte) error {
	if s.phase == "output" {
		return errors.New("disk full")
	}
	return s.Store.WriteOutput(stream, data)
}

func (s failingStore) Append(o watchdog.Observation) error {
	if s.phase == "append" {
		return errors.New("disk full")
	}
	return s.Store.Append(o)
}

func (s failingStore) Finish(result watchdog.RunResult) error {
	err := s.Store.Finish(result)
	if s.phase == "finish" {
		return errors.Join(err, errors.New("cannot sync result"))
	}
	return err
}

func TestStorageErrorsAreWatchdogFailures(t *testing.T) {
	for _, phase := range []string{"begin", "log", "output", "append", "finish"} {
		t.Run(phase, func(t *testing.T) {
			c := runConfig(t)
			mode := "complete"
			if phase == "output" || phase == "append" {
				mode = "stream"
			}
			started := time.Now()
			result, err := run(t, c, &fixtureDriver{mode: mode}, failingStore{Store: &storage.FileStore{}, phase: phase})
			if err == nil || result.Reason != watchdog.ReasonStorageFailed {
				t.Fatalf("result=%#v, error=%v", result, err)
			}
			if phase == "begin" && result.Exit.Code != nil {
				t.Fatal("process started after a store initialization failure")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("storage failure did not stop the process promptly")
			}
		})
	}
}

func TestRestartRecognizedErrorsAndAggregateStatistics(t *testing.T) {
	for _, kind := range []string{"crash", "sanitizer", "timeout", "out_of_memory"} {
		t.Run(kind, func(t *testing.T) {
			c := runConfig(t)
			c.Restart = watchdog.RestartOnCrash
			result, err := run(t, c, &fixtureDriver{mode: "flaky", errorKind: kind}, &storage.FileStore{})
			if err != nil || result.Reason != watchdog.ReasonProcessExited || result.Outcome != watchdog.OutcomeCompleted {
				t.Fatalf("result=%#v error=%v", result, err)
			}
			stats := result.Statistics
			if stats.Attempts != 3 || stats.Restarts != 2 || stats.TargetErrors != 2 || stats.ErrorsByKind[kind] != 2 {
				t.Fatalf("duplicate diagnostics inflated counts: %#v", stats)
			}
			if stats.Metrics["executions"] != 30 || stats.Metrics["libfuzzer.coverage"] != 3 || stats.Metrics["corpus_entries"] != 2 || stats.Metrics["rss_bytes"] != 24*1024*1024 {
				t.Fatalf("incorrect aggregation: %#v", stats.Metrics)
			}
			if kind == "crash" && stats.ElapsedTime > 1800*time.Millisecond {
				t.Fatal("unexpected restart delay")
			}
			data, err := os.ReadFile(result.Files.Result)
			if err != nil || strings.Contains(string(data), `"findings":`) || strings.Contains(string(data), `"stdout":`) || strings.Contains(string(data), `"stderr":`) {
				t.Fatalf("obsolete result data: %s / %v", data, err)
			}
			data, _ = os.ReadFile(result.Files.Metrics)
			seen := make(map[int]bool)
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var o watchdog.Observation
				if err := json.Unmarshal([]byte(line), &o); err != nil {
					t.Fatal(err)
				}
				seen[o.Attempt] = true
			}
			if len(seen) != 3 {
				t.Fatalf("missing attempt ids: %v", seen)
			}
		})
	}
}

func TestSuccessfulAndUnknownExitsAreNotRestarted(t *testing.T) {
	for _, mode := range []string{"complete", "failure"} {
		c := runConfig(t)
		c.Restart = watchdog.RestartOnCrash
		result, err := run(t, c, &fixtureDriver{mode: mode}, &storage.FileStore{})
		if err != nil || result.Statistics.Attempts != 1 || result.Statistics.Restarts != 0 {
			t.Fatalf("mode=%s result=%#v err=%v", mode, result, err)
		}
	}
	c := runConfig(t)
	result, err := run(t, c, &fixtureDriver{mode: "flaky"}, &storage.FileStore{})
	if err != nil || result.Statistics.Attempts != 1 || result.Outcome != watchdog.OutcomeTargetError {
		t.Fatalf("never restarted: %#v / %v", result, err)
	}
}

func TestPostExitWorkDoesNotConsumeFuzzingBudgets(t *testing.T) {
	for _, limit := range []string{"total", "no-progress"} {
		t.Run(limit, func(t *testing.T) {
			c := runConfig(t)
			c.Restart, c.ShutdownTimeout = watchdog.RestartOnCrash, 500*time.Millisecond
			if limit == "total" {
				c.FuzzingTimeout = 300 * time.Millisecond
			} else {
				c.NoProgressTimeout = 300 * time.Millisecond
			}
			result, err := run(t, c, &fixtureDriver{mode: "flaky", drainDelay: 150 * time.Millisecond}, &storage.FileStore{})
			if err != nil || result.Reason != watchdog.ReasonProcessExited || result.Statistics.Attempts != 3 {
				t.Fatalf("inactive work consumed %s budget: %#v / %v", limit, result, err)
			}
			if result.Statistics.ElapsedTime-result.Statistics.ActiveTime < 450*time.Millisecond {
				t.Fatalf("post-exit delay was counted as active: %#v", result.Statistics)
			}
		})
	}
}

func TestActiveLimitsAndCoveragePersistAcrossRestarts(t *testing.T) {
	for _, reason := range []watchdog.StopReason{watchdog.ReasonFuzzingTimeout, watchdog.ReasonNoProgress} {
		t.Run(string(reason), func(t *testing.T) {
			c := runConfig(t)
			c.Restart, c.ShutdownTimeout = watchdog.RestartOnCrash, 300*time.Millisecond
			if reason == watchdog.ReasonFuzzingTimeout {
				c.FuzzingTimeout = 150 * time.Millisecond
			} else {
				c.NoProgressTimeout = 150 * time.Millisecond
			}
			result, err := run(t, c, &fixtureDriver{mode: "repeat", drainDelay: 60 * time.Millisecond}, &storage.FileStore{})
			if err != nil || result.Reason != reason || result.Outcome != watchdog.OutcomeStopped || result.Statistics.Attempts < 2 || result.Statistics.TargetErrors < 1 {
				t.Fatalf("result=%#v error=%v", result, err)
			}
		})
	}
}

type restartGateStore struct {
	watchdog.Store
	ready   chan struct{}
	release chan struct{}
}

func (s restartGateStore) Log(message string) error {
	if strings.HasPrefix(message, "Restarting after") {
		close(s.ready)
		<-s.release
	}
	return s.Store.Log(message)
}

func TestSignalBetweenAttemptsPreventsNextLaunch(t *testing.T) {
	c := runConfig(t)
	c.Restart = watchdog.RestartOnCrash
	ctx, cancel := context.WithCancelCause(context.Background())
	ready, release := make(chan struct{}), make(chan struct{})
	defer func() {
		cancel(nil)
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	done := make(chan struct{})
	var result watchdog.RunResult
	var err error
	go func() {
		result, err = (watchdog.Runner{Driver: &fixtureDriver{mode: "repeat"}, Store: restartGateStore{Store: &storage.FileStore{}, ready: ready, release: release}}).Run(ctx, c)
		close(done)
	}()
	select {
	case <-ready:
	case <-done:
		t.Fatalf("session ended early: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("no restart")
	}
	cancel(&watchdog.SignalError{Signal: syscall.SIGINT})
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("signal was not handled")
	}
	if err != nil || result.Reason != watchdog.ReasonInterrupted || result.StopSignal != "SIGINT" || result.Statistics.Attempts != 1 {
		t.Fatalf("result=%#v error=%v", result, err)
	}
}

func TestStartAndMonitorErrorsArePersisted(t *testing.T) {
	for _, tc := range []struct {
		driver *fixtureDriver
		reason watchdog.StopReason
	}{
		{&fixtureDriver{executable: "/nonexistent/yafwd-target"}, watchdog.ReasonStartFailed},
		{&fixtureDriver{mode: "silent", monitorError: true}, watchdog.ReasonMonitorFailed},
	} {
		t.Run(string(tc.reason), func(t *testing.T) {
			result, err := run(t, runConfig(t), tc.driver, &storage.FileStore{})
			if err == nil || result.Reason != tc.reason {
				t.Fatalf("result=%#v, error=%v", result, err)
			}
			data, err := os.ReadFile(result.Files.Result)
			if err != nil || !strings.Contains(string(data), string(tc.reason)) {
				t.Fatalf("failure not recorded: %s / %v", data, err)
			}
		})
	}
}

func TestRawLogsPreserveOversizedLines(t *testing.T) {
	result, err := run(t, runConfig(t), &fixtureDriver{mode: "long-output"}, &storage.FileStore{})
	if err != nil || result.Statistics.Metrics["executions"] != 100 {
		t.Fatalf("result=%#v, error=%v", result, err)
	}
	data, _ := os.ReadFile(result.Files.Log)
	if !strings.Contains(string(data), strings.Repeat("x", 2*1024*1024)+"\n") {
		t.Fatal("raw log was truncated")
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func processRunning(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// A killed orphan can remain a zombie until the container's init reaps it.
	end := strings.LastIndex(string(data), ")")
	return end < 0 || !strings.HasPrefix(string(data[end+1:]), " Z")
}
