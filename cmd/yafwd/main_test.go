//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func TestStandaloneCLIEndToEnd(t *testing.T) {
	for _, finding := range []bool{false, true} {
		name := "completed"
		if finding {
			name = "finding"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			shell, err := exec.LookPath("sh")
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "fuzz target")
			body := "#!" + shell + "\n" +
				"printf '%s\\n' \"$@\"\n" +
				"printf '#2 INITED cov: 2 ft: 3 corp: 1/1b\\n#10 NEW cov: 3 ft: 4\\n' >&2\n"
			if finding {
				body += "for arg do\n case \"$arg\" in -artifact_prefix=*) prefix=${arg#-artifact_prefix=} ;; esac\ndone\n" +
					"printf 'crashing input' > \"${prefix}crash-test\"\n" +
					"printf 'ERROR: libFuzzer: deadly signal\\nTest unit written to %scrash-test\\n' \"$prefix\" >&2\nexit 77\n"
			}
			if err := os.WriteFile(target, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			code := run(ctx, []string{"-e", "libfuzzer", "--runs-dir", filepath.Join(dir, "runs"), "--output", filepath.Join(dir, "new corpus"), "--artifacts", filepath.Join(dir, "artifacts"), "--", target, "-dict=literal $HOME words"}, &stdout, &stderr)
			wantCode := 0
			if finding {
				wantCode = 1
			}
			if code != wantCode {
				t.Fatalf("exit=%d: %s", code, stderr.String())
			}
			var result watchdog.RunResult
			records, _ := filepath.Glob(filepath.Join(dir, "runs", "*", "result.json"))
			if len(records) != 1 {
				t.Fatalf("missing result: %s", stderr.String())
			}
			data, _ := os.ReadFile(records[0])
			if json.Valid(stdout.Bytes()) || !strings.Contains(stdout.String(), "Fuzzing session result") {
				t.Fatalf("expected text report: %s", stdout.String())
			}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("invalid result: %s / %v", stdout.String(), err)
			}
			log, err := os.ReadFile(result.Files.Log)
			if err != nil || !strings.Contains(string(log), "-dict=literal $HOME words\n") {
				t.Fatalf("command arguments were expanded: %q / %v", log, err)
			}
			if result.Statistics.Metrics["libfuzzer.coverage"] != 3 || result.OutputDir != filepath.Join(dir, "new corpus") {
				t.Fatalf("unexpected result: %#v", result)
			}
			if finding {
				if _, err := os.Stat(filepath.Join(result.ArtifactsDir, "crash-test")); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHelpAndInvalidInputExitCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run(context.Background(), []string{"--help"}, &stdout, &stderr); got != 0 || !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("help: exit=%d, output=%s", got, stderr.String())
	}
	if got := run(context.Background(), []string{"--engine=afl", "--", "target"}, &stdout, &stderr); got != 2 {
		t.Fatalf("invalid input exit=%d", got)
	}
}

func TestInterruptedAndLimitedRunExitCodes(t *testing.T) {
	for _, tc := range []struct {
		result watchdog.RunResult
		want   int
	}{
		{watchdog.RunResult{Reason: watchdog.ReasonInterrupted, StopSignal: "SIGINT"}, 130},
		{watchdog.RunResult{Reason: watchdog.ReasonInterrupted, StopSignal: "SIGTERM"}, 143},
		{watchdog.RunResult{Reason: watchdog.ReasonFuzzingTimeout, Outcome: watchdog.OutcomeSignaled}, 0},
		{watchdog.RunResult{Reason: watchdog.ReasonNoProgress, Outcome: watchdog.OutcomeTargetError}, 0},
	} {
		if got := exitCode(tc.result); got != tc.want {
			t.Errorf("exit=%d, want=%d for %#v", got, tc.want, tc.result)
		}
	}
}
