// Package storage persists a run independently of any controller connection.
package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

type FileStore struct {
	mu         sync.Mutex
	paths      watchdog.RunFiles
	journal    *os.File
	metrics    *os.File
	lastStream watchdog.Stream
	lineStart  bool
	started    bool
	finished   bool
}

var _ watchdog.Store = (*FileStore)(nil)

func (s *FileStore) Begin(config watchdog.RunConfig, launch watchdog.LaunchSpec, at time.Time) (watchdog.RunFiles, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return watchdog.RunFiles{}, fmt.Errorf("store already used for a run")
	}
	if err := os.MkdirAll(config.RunsDir, 0o700); err != nil {
		return watchdog.RunFiles{}, err
	}
	dir, err := os.MkdirTemp(config.RunsDir, at.UTC().Format("20060102T150405.000000000Z")+"-")
	if err != nil {
		return watchdog.RunFiles{}, err
	}
	s.paths = watchdog.RunFiles{
		Directory: dir,
		Config:    filepath.Join(dir, "config.json"),
		Log:       filepath.Join(dir, "run.log"),
		Metrics:   filepath.Join(dir, "metrics.jsonl"),
		Result:    filepath.Join(dir, "result.json"),
	}
	var opened []*os.File
	open := func(path string) (*os.File, error) {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			opened = append(opened, file)
		}
		return file, err
	}
	success := false
	defer func() {
		if !success {
			for _, file := range opened {
				file.Close()
			}
			// Only this freshly-created run directory is removed.
			os.RemoveAll(dir)
		}
	}()
	if s.journal, err = open(s.paths.Log); err != nil {
		return watchdog.RunFiles{}, err
	}
	if s.metrics, err = open(s.paths.Metrics); err != nil {
		return watchdog.RunFiles{}, err
	}
	record := struct {
		Version   int                 `json:"version"`
		StartedAt time.Time           `json:"started_at"`
		Config    watchdog.RunConfig  `json:"config"`
		Launch    watchdog.LaunchSpec `json:"launch"`
	}{2, at, config, launch}
	if err := writeJSON(s.paths.Config, record); err != nil {
		return watchdog.RunFiles{}, err
	}
	s.started, success = true, true
	s.lineStart = true
	return s.paths, nil
}

func (s *FileStore) WriteOutput(stream watchdog.Stream, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.finished {
		return fmt.Errorf("store is not open")
	}
	if stream != watchdog.Stdout && stream != watchdog.Stderr {
		return fmt.Errorf("unknown output stream %q", stream)
	}
	return s.writeLog(stream, data)
}

func (s *FileStore) Log(message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.finished {
		return fmt.Errorf("store is not open")
	}
	for _, line := range strings.Split(strings.TrimSuffix(message, "\n"), "\n") {
		if err := s.writeLog(watchdog.Stream("watchdog"), []byte("[watchdog] "+line+"\n")); err != nil {
			return err
		}
	}
	return nil
}

func (s *FileStore) writeLog(stream watchdog.Stream, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !s.lineStart && stream != s.lastStream {
		if err := writeAll(s.journal, []byte{'\n'}); err != nil {
			return err
		}
	}
	if err := writeAll(s.journal, data); err != nil {
		return err
	}
	s.lastStream, s.lineStart = stream, data[len(data)-1] == '\n'
	return nil
}

func (s *FileStore) Append(observation watchdog.Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.finished {
		return fmt.Errorf("store is not open")
	}
	data, err := json.Marshal(observation)
	if err != nil {
		return err
	}
	return writeAll(s.metrics, append(data, '\n'))
}

func (s *FileStore) Finish(result watchdog.RunResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.finished {
		return fmt.Errorf("store is not open")
	}
	s.finished = true
	var flushErr error
	for _, file := range []*os.File{s.journal, s.metrics} {
		flushErr = errors.Join(flushErr, file.Sync(), file.Close())
	}
	if flushErr != nil {
		result.Reason = watchdog.ReasonStorageFailed
		if result.Error != "" {
			result.Error += "\n"
		}
		result.Error += fmt.Sprintf("flush run files: %v", flushErr)
	}
	// A result file is published only after output and metrics have been closed.
	// Record a flush failure too if the filesystem still permits writing it.
	return errors.Join(flushErr, writeJSON(s.paths.Result, result))
}

func writeAll(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func writeJSON(path string, value any) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	encoder := json.NewEncoder(temp)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	err = errors.Join(encodeErr, temp.Sync(), temp.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
