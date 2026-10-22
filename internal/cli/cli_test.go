package cli

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func TestParseKeepsCommandArgumentsAndUsesCurrentDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	command := []string{"./target with spaces", "-dict=words with spaces", "-runs=10"}
	args := append([]string{"-e", "libFuzzer", "-i", "seeds", "-o", "new corpus", "--fuzzing-timeout", "30m", "--no-progress-timeout", "120", "--"}, command...)
	c, err := Parse(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Command, command) {
		t.Fatalf("command changed: %#v", c.Command)
	}
	if c.OutputDir != filepath.Join(cwd, "new corpus") || c.InputDir != filepath.Join(cwd, "seeds") || c.WorkDir != cwd {
		t.Fatalf("unexpected paths: %#v", c)
	}
	if c.FuzzingTimeout != 30*time.Minute || c.NoProgressTimeout != 2*time.Minute {
		t.Fatalf("unexpected timeouts: %#v", c)
	}
}

func TestDefaultsAndDurations(t *testing.T) {
	c, err := Parse([]string{"-e", "libfuzzer", "--", "target"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	if c.OutputDir != filepath.Join(cwd, "findings") || c.InputDir != "" || c.ArtifactsDir != filepath.Join(cwd, "artifacts") || c.RunsDir != filepath.Join(cwd, "yafwd-runs") || c.Restart != watchdog.RestartNever || c.ShutdownTimeout != 5*time.Second {
		t.Fatalf("unexpected defaults: %#v", c)
	}
	for value, want := range map[string]time.Duration{"60": time.Minute, "1.5": 1500 * time.Millisecond, "500ms": 500 * time.Millisecond, "1h30m": 90 * time.Minute, "0": 0} {
		t.Run(value, func(t *testing.T) {
			c, err := Parse([]string{"-e", "libfuzzer", "--fuzzing-timeout", value, "--no-progress-timeout", value, "--restart=on-crash", "--", "target"}, io.Discard)
			if err != nil || c.FuzzingTimeout != want || c.NoProgressTimeout != want || c.Restart != watchdog.RestartOnCrash {
				t.Fatalf("config=%#v err=%v", c, err)
			}
		})
	}
	c, err = Parse([]string{"-e", "libfuzzer", "--shutdown-timeout", "0.25", "--", "target"}, io.Discard)
	if err != nil || c.ShutdownTimeout != 250*time.Millisecond {
		t.Fatalf("shutdown=%s error=%v", c.ShutdownTimeout, err)
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	for name, args := range map[string][]string{
		"missing engine":        {"--", "target"},
		"missing separator":     {"-e", "libfuzzer", "target"},
		"missing command":       {"-e", "libfuzzer", "--"},
		"unsupported engine":    {"--engine", "afl", "--", "target"},
		"negative limit":        {"-e", "libfuzzer", "--fuzzing-timeout=-1s", "--", "target"},
		"invalid duration":      {"-e", "libfuzzer", "--no-progress-timeout=forever", "--", "target"},
		"overflow":              {"-e", "libfuzzer", "--fuzzing-timeout=999999999999999999999", "--", "target"},
		"zero shutdown":         {"-e", "libfuzzer", "--shutdown-timeout=0", "--", "target"},
		"unexpected positional": {"-e", "libfuzzer", "other", "--", "target"},
		"empty output":          {"-e", "libfuzzer", "--output=", "--", "target"},
		"old time limit":        {"-e", "libfuzzer", "--time-limit=1m", "--", "target"},
		"workdir removed":       {"-e", "libfuzzer", "--workdir=.", "--", "target"},
		"restart mode":          {"-e", "libfuzzer", "--restart=always", "--", "target"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(args, io.Discard); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestHelpDoesNotRequireCommand(t *testing.T) {
	_, err := Parse([]string{"--help"}, io.Discard)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("got %v", err)
	}
}
