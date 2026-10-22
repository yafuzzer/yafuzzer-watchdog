package libfuzzer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func config(t *testing.T) watchdog.RunConfig {
	t.Helper()
	c := watchdog.DefaultConfig()
	c.Engine = "libfuzzer"
	c.WorkDir = t.TempDir()
	c.Command = []string{"./target with spaces", "-dict=some words", "-runs=123"}
	resolved, err := c.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestPrepareMapsDirectoriesAndPreservesArguments(t *testing.T) {
	c := config(t)
	c.InputDir = filepath.Join(c.WorkDir, "seed corpus")
	if err := os.Mkdir(c.InputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := append([]string(nil), c.Command...)
	spec, err := (&Driver{}).Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Executable != filepath.Join(c.WorkDir, "target with spaces") {
		t.Fatalf("unexpected executable: %s", spec.Executable)
	}
	if spec.Args[0] != c.OutputDir || spec.Args[1] != c.InputDir || !strings.HasSuffix(spec.Args[2], string(os.PathSeparator)) {
		t.Fatalf("unexpected corpus/artifact args: %#v", spec.Args)
	}
	if !reflect.DeepEqual(spec.Args[len(spec.Args)-2:], original[1:]) || !reflect.DeepEqual(c.Command, original) {
		t.Fatalf("arguments changed: %#v", spec.Args)
	}
	if _, err := os.Stat(c.OutputDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Prepare must not create directories: %v", err)
	}
}

func TestPrepareRejectsIncompatibleArguments(t *testing.T) {
	for _, arg := range []string{
		"-jobs=1", "-workers=1", "-fork=2", "-merge=1", "-minimize_crash=1", "-help=1",
		"-artifact_prefix=other/", "-exact_artifact_path=crash", "-verbosity=0",
		"-close_fd_mask=2", "-max_total_time=10", "-stale_corpus_timeout=1", "another-corpus",
	} {
		t.Run(arg, func(t *testing.T) {
			c := config(t)
			c.Command = []string{"target", arg}
			if _, err := (&Driver{}).Prepare(c); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestPrepareRejectsOverlappingAndSymlinkedPaths(t *testing.T) {
	c := config(t)
	c.ArtifactsDir = filepath.Join(c.OutputDir, "crashes")
	if _, err := (&Driver{}).Prepare(c); err == nil {
		t.Fatal("nested paths accepted")
	}
	c = config(t)
	if err := os.Mkdir(c.OutputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(c.WorkDir, "alias")
	if err := os.Symlink(c.OutputDir, alias); err != nil {
		t.Fatal(err)
	}
	c.ArtifactsDir = filepath.Join(alias, "new")
	if _, err := (&Driver{}).Prepare(c); err == nil {
		t.Fatal("symlinked overlap accepted")
	}
}

func TestObserveCoverageAndMissingMetrics(t *testing.T) {
	log := "initializing the target\n" +
		"#2 INITED cov: 5 ft: 8 corp: 1/4b exec/s: 0 rss: 23Mb\n" +
		"#18 NEW cov: 6 ft: 10 corp: 2/8b exec/s: 120 rss: 24Mb\n" +
		"#29 REDUCE cov: 6 ft: 10 corp: 2/6b exec/s: 150 rss: 24Mb\n" +
		"#32 NEW cov: 6 ft: 10 corp: 3/9b\n" +
		"#64 pulse cov: 6 ft: 11\n" +
		"#72 NEW cov: 5 ft: 9\n" +
		"#80 NEW cov: 6 ft: 11\n" +
		"#90 DONE cov: 6 ft: 11" // No final newline.
	var observations []watchdog.Observation
	err := (&Driver{}).Observe(context.Background(), watchdog.Sources{
		Stdout: strings.NewReader("unrelated target output\n"), Stderr: strings.NewReader(log),
	}, func(o watchdog.Observation) error {
		observations = append(observations, o)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantProgress := []bool{false, true, false, false, true, false, false, false}
	if len(observations) != len(wantProgress) {
		t.Fatalf("got %d observations", len(observations))
	}
	for i, o := range observations {
		if o.Progress != wantProgress[i] {
			t.Errorf("%s at %d: progress=%v", o.Event, i, o.Progress)
		}
	}
	if observations[0].Metrics["rss_bytes"] != 23*1024*1024 || observations[0].Metrics["corpus_bytes"] != 4 {
		t.Fatalf("incorrect sizes: %#v", observations[0].Metrics)
	}
	if _, exists := observations[4].Metrics["execs_per_second"]; exists {
		t.Fatal("missing rate must not be zero-filled")
	}
}

func TestObserveFindingsAndLongUnknownLines(t *testing.T) {
	log := strings.Repeat("x", 2*1024*1024) + "\n" +
		"==42== ERROR: libFuzzer: deadly signal\n" +
		"artifact_prefix='./'; Test unit written to artifacts/crash-one\n"
	var findings []watchdog.Finding
	err := (&Driver{}).Observe(context.Background(), watchdog.Sources{
		Stdout: strings.NewReader(""), Stderr: strings.NewReader(log), WorkDir: "/work",
	}, func(o watchdog.Observation) error {
		findings = append(findings, *o.Finding)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Kind != "crash" || findings[1].Artifact != "/work/artifacts/crash-one" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestCoverageHighWaterSurvivesAttemptsAndResetsForNewSession(t *testing.T) {
	d := &Driver{}
	observe := func(log string) []bool {
		var progress []bool
		err := d.Observe(context.Background(), watchdog.Sources{Stdout: strings.NewReader(""), Stderr: strings.NewReader(log)}, func(o watchdog.Observation) error {
			progress = append(progress, o.Progress)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return progress
	}
	first := "#2 INITED cov: 2 ft: 2\n#10 NEW cov: 7 ft: 7\n"
	if got := observe(first); !reflect.DeepEqual(got, []bool{false, true}) {
		t.Fatalf("first attempt: %v", got)
	}
	second := "#2 INITED cov: 2 ft: 2\n#4 NEW cov: 4 ft: 4\n#10 NEW cov: 7 ft: 7\n#20 NEW cov: 8 ft: 8\n"
	if got := observe(second); !reflect.DeepEqual(got, []bool{false, false, false, true}) {
		t.Fatalf("old coverage counted again: %v", got)
	}
	if _, err := d.Prepare(config(t)); err != nil {
		t.Fatal(err)
	}
	if got := observe(first); !reflect.DeepEqual(got, []bool{false, true}) {
		t.Fatalf("new session inherited old progress: %v", got)
	}
}

func TestInterpretAllRecognizedTargetErrors(t *testing.T) {
	code := 77
	for _, kind := range []string{"crash", "sanitizer", "leak", "timeout", "out_of_memory"} {
		outcome := (&Driver{}).Interpret(watchdog.ExitStatus{Code: &code}, watchdog.AttemptEvidence{Kinds: map[string]bool{kind: true}})
		if outcome.Outcome != watchdog.OutcomeTargetError || outcome.ErrorKind != kind {
			t.Fatalf("%s: %#v", kind, outcome)
		}
	}
}

func TestInterpretDistinguishesFindingAndProcessFailure(t *testing.T) {
	zero, failure := 0, 77
	for _, tc := range []struct {
		exit     watchdog.ExitStatus
		evidence watchdog.AttemptEvidence
		want     watchdog.Outcome
	}{
		{watchdog.ExitStatus{Code: &zero}, watchdog.AttemptEvidence{}, watchdog.OutcomeCompleted},
		{watchdog.ExitStatus{Code: &failure}, watchdog.AttemptEvidence{}, watchdog.OutcomeFailed},
		{watchdog.ExitStatus{Code: &failure}, watchdog.AttemptEvidence{Kinds: map[string]bool{"crash": true}}, watchdog.OutcomeTargetError},
		{watchdog.ExitStatus{Signal: "SIGTERM"}, watchdog.AttemptEvidence{}, watchdog.OutcomeSignaled},
		{watchdog.ExitStatus{Signal: "SIGSEGV"}, watchdog.AttemptEvidence{}, watchdog.OutcomeTargetError},
	} {
		if got := (&Driver{}).Interpret(tc.exit, tc.evidence).Outcome; got != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
}

func TestObserveFinalStatistics(t *testing.T) {
	log := "#10 DONE cov: 4 ft: 8\n" +
		"stat::number_of_executed_units: 98765\n" +
		"stat::average_exec_per_sec:     1234\n" +
		"stat::new_units_added:          3\n" +
		"stat::slowest_unit_time_sec:    0\n" +
		"stat::peak_rss_mb:              27\n" +
		"stat::average_exec_per_sec:     NaN\n"
	metrics := make(map[string]float64)
	err := (&Driver{}).Observe(context.Background(), watchdog.Sources{
		Stdout: strings.NewReader(""), Stderr: strings.NewReader(log),
	}, func(o watchdog.Observation) error {
		if o.Progress {
			t.Error("final statistics must not reset the progress timer")
		}
		for key, value := range o.Metrics {
			metrics[key] = value
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if metrics["executions"] != 98765 || metrics["execs_per_second"] != 1234 || metrics["peak_rss_bytes"] != 27*1024*1024 {
		t.Fatalf("incomplete final metrics: %#v", metrics)
	}
}
