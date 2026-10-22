package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func begin(t *testing.T) (*FileStore, watchdog.RunFiles) {
	t.Helper()
	c := watchdog.DefaultConfig()
	c.RunsDir = t.TempDir()
	c.Command = []string{"target", "-dict=two words"}
	s := &FileStore{}
	paths, err := s.Begin(c, watchdog.LaunchSpec{Executable: "target"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return s, paths
}

func TestUnifiedJournalSeparatesPartialLinesAndPrefixesMessages(t *testing.T) {
	s, paths := begin(t)
	if err := s.WriteOutput(watchdog.Stdout, []byte("partial stdout")); err != nil {
		t.Fatal(err)
	}
	if err := s.Log("First message\nSecond message"); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteOutput(watchdog.Stderr, []byte("partial stderr")); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteOutput(watchdog.Stdout, []byte("next output\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Log("Done"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(watchdog.RunResult{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.Log)
	want := "partial stdout\n[watchdog] First message\n[watchdog] Second message\npartial stderr\nnext output\n[watchdog] Done\n"
	if err != nil || string(data) != want {
		t.Fatalf("journal=%q error=%v", data, err)
	}
	for _, name := range []string{"stdout.log", "stderr.log"} {
		if _, err := os.Stat(filepath.Join(paths.Directory, name)); !os.IsNotExist(err) {
			t.Fatalf("old separate log created: %s", name)
		}
	}
}

func TestRunFilesAndConcurrentOutput(t *testing.T) {
	s, paths := begin(t)
	var writers sync.WaitGroup
	for _, stream := range []watchdog.Stream{watchdog.Stdout, watchdog.Stderr} {
		writers.Add(1)
		go func(stream watchdog.Stream) {
			defer writers.Done()
			for i := 0; i < 100; i++ {
				if err := s.WriteOutput(stream, []byte("raw\x00bytes\n")); err != nil {
					t.Error(err)
					return
				}
			}
		}(stream)
	}
	if err := s.Append(watchdog.Observation{Engine: "libfuzzer", Metrics: map[string]float64{"execs_per_second": 0}}); err != nil {
		t.Fatal(err)
	}
	writers.Wait()
	if err := s.Finish(watchdog.RunResult{Reason: watchdog.ReasonProcessExited, Files: paths}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.Log} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != strings.Repeat("raw\x00bytes\n", 200) {
			t.Fatalf("corrupt raw output %s: %v", path, err)
		}
	}
	data, _ := os.ReadFile(paths.Metrics)
	if !strings.Contains(string(data), `"execs_per_second":0`) || strings.Contains(string(data), "coverage") {
		t.Fatalf("missing metrics were zero-filled: %s", data)
	}
	for _, path := range []string{paths.Config, paths.Result} {
		data, err := os.ReadFile(path)
		if err != nil || !json.Valid(data) {
			t.Fatalf("invalid JSON at %s: %v", path, err)
		}
	}
	if err := s.WriteOutput(watchdog.Stdout, []byte("late write")); err == nil {
		t.Fatal("write succeeded after finalization")
	}
}

func TestBeginFailsBeforeRunWhenRootIsAFile(t *testing.T) {
	c := watchdog.DefaultConfig()
	c.RunsDir = filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(c.RunsDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&FileStore{}).Begin(c, watchdog.LaunchSpec{}, time.Now()); err == nil {
		t.Fatal("accepted a file as the runs directory")
	}
}

func TestFlushErrorIsRecordedIfResultCanStillBeWritten(t *testing.T) {
	s, paths := begin(t)
	if err := s.journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(watchdog.RunResult{Reason: watchdog.ReasonProcessExited}); err == nil {
		t.Fatal("closed output file was not reported")
	}
	data, err := os.ReadFile(paths.Result)
	if err != nil {
		t.Fatal(err)
	}
	var result watchdog.RunResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Reason != watchdog.ReasonStorageFailed || result.Error == "" {
		t.Fatalf("storage failure not recorded: %s", data)
	}
}
