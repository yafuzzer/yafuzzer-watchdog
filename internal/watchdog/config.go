package watchdog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolve validates shared settings and makes paths absolute relative to WorkDir.
// It does not create files or change the caller's configuration.
func (c RunConfig) Resolve() (RunConfig, error) {
	if len(c.Command) == 0 || strings.TrimSpace(c.Command[0]) == "" {
		return c, fmt.Errorf("a fuzzing command is required after --")
	}
	if c.Engine == "" {
		return c, fmt.Errorf("--engine is required")
	}
	if c.Restart != RestartNever && c.Restart != RestartOnCrash {
		return c, fmt.Errorf("unsupported restart mode %q: use never or on-crash", c.Restart)
	}
	if c.FuzzingTimeout < 0 || c.NoProgressTimeout < 0 {
		return c, fmt.Errorf("time limits must be non-negative (0 disables a limit)")
	}
	if c.ShutdownTimeout <= 0 {
		return c, fmt.Errorf("shutdown timeout must be positive")
	}
	var err error
	if c.WorkDir == "" {
		c.WorkDir, err = os.Getwd()
	} else {
		c.WorkDir, err = filepath.Abs(c.WorkDir)
	}
	if err != nil {
		return c, fmt.Errorf("resolve working directory: %w", err)
	}
	info, err := os.Stat(c.WorkDir)
	if err != nil {
		return c, fmt.Errorf("working directory: %w", err)
	}
	if !info.IsDir() {
		return c, fmt.Errorf("working directory is not a directory: %s", c.WorkDir)
	}
	resolve := func(path string) string {
		if filepath.IsAbs(path) {
			return filepath.Clean(path)
		}
		return filepath.Join(c.WorkDir, path)
	}
	if c.OutputDir == "" || c.ArtifactsDir == "" || c.RunsDir == "" {
		return c, fmt.Errorf("output, artifacts and runs directories must not be empty")
	}
	if c.InputDir != "" {
		c.InputDir = resolve(c.InputDir)
	}
	c.OutputDir = resolve(c.OutputDir)
	c.ArtifactsDir = resolve(c.ArtifactsDir)
	c.RunsDir = resolve(c.RunsDir)
	c.Command = append([]string(nil), c.Command...)
	return c, nil
}
