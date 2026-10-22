package libfuzzer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

var statsHeader = regexp.MustCompile(`^#([0-9]+)\s+(INITED|NEW|REDUCE|pulse|DONE|RELOAD)\b`)

func (d *Driver) Observe(ctx context.Context, src watchdog.Sources, emit func(watchdog.Observation) error) error {
	if d.highWater == nil {
		d.highWater = make(map[string]float64)
	}
	errs := make(chan error, 2)
	go func() {
		_, err := io.Copy(io.Discard, src.Stdout)
		errs <- err
	}()
	go func() {
		p := parser{workDir: src.WorkDir, highWater: d.highWater}
		errs <- readLines(src.Stderr, func(line string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if observation, ok := p.parse(line); ok {
				return emit(observation)
			}
			return nil
		})
	}()
	// Runner closes the sources if shutdown cannot drain them. Waiting for both
	// readers here ensures no writes race with Store.Finish.
	return errors.Join(<-errs, <-errs)
}

// Limit parsing memory without imposing a line-length limit on the raw logs.
// Oversized lines are drained and preserved by Runner's logging readers.
func readLines(src io.Reader, visit func(string) error) error {
	reader := bufio.NewReaderSize(src, 32*1024)
	var line []byte
	skipping := false
	for {
		part, prefix, err := reader.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if !skipping {
			if len(line)+len(part) > 1024*1024 {
				line = nil
				skipping = true
			} else {
				line = append(line, part...)
			}
		}
		if !prefix {
			if !skipping {
				if err := visit(string(line)); err != nil {
					return err
				}
			}
			line = line[:0]
			skipping = false
		}
	}
}

type parser struct {
	workDir   string
	highWater map[string]float64
}

func (p *parser) parse(line string) (watchdog.Observation, bool) {
	o := watchdog.Observation{At: time.Now(), Engine: "libfuzzer"}
	if strings.HasPrefix(line, "stat::") {
		name, token, ok := strings.Cut(line, ": ")
		if !ok {
			return o, false
		}
		key := map[string]string{
			"stat::number_of_executed_units": "executions",
			"stat::average_exec_per_sec":     "execs_per_second",
			"stat::new_units_added":          "libfuzzer.new_units_added",
			"stat::slowest_unit_time_sec":    "libfuzzer.slowest_unit_time_seconds",
			"stat::peak_rss_mb":              "peak_rss_bytes",
		}[name]
		value, err := strconv.ParseFloat(strings.TrimSpace(token), 64)
		if key == "" || err != nil || value < 0 || math.IsInf(value, 0) || math.IsNaN(value) {
			return o, false
		}
		if key == "peak_rss_bytes" {
			value *= 1024 * 1024
			if math.IsInf(value, 0) {
				return o, false
			}
		}
		o.Event = "final_stats"
		o.Metrics = map[string]float64{key: value}
		return o, true
	}
	if match := statsHeader.FindStringSubmatch(line); match != nil {
		o.Event = match[2]
		o.Metrics = make(map[string]float64)
		if value, err := strconv.ParseUint(match[1], 10, 64); err == nil {
			o.Metrics["executions"] = float64(value)
		}
		fields := strings.Fields(line[len(match[0]):])
		for i := 0; i+1 < len(fields); i++ {
			key, token := fields[i], fields[i+1]
			switch key {
			case "cov:", "ft:", "exec/s:":
				value, err := strconv.ParseUint(token, 10, 64)
				if err == nil {
					name := map[string]string{"cov:": "libfuzzer.coverage", "ft:": "libfuzzer.features", "exec/s:": "execs_per_second"}[key]
					o.Metrics[name] = float64(value)
				}
			case "corp:":
				count, size, ok := strings.Cut(token, "/")
				if ok {
					if value, err := strconv.ParseUint(count, 10, 64); err == nil {
						o.Metrics["corpus_entries"] = float64(value)
					}
					if value, ok := parseSize(size, 1); ok {
						o.Metrics["corpus_bytes"] = value
					}
				}
			case "rss:":
				if value, ok := parseSize(token, 1024*1024); ok {
					o.Metrics["rss_bytes"] = value
				}
			}
		}
		for _, key := range []string{"libfuzzer.coverage", "libfuzzer.features"} {
			if value, exists := o.Metrics[key]; exists {
				previous, seen := p.highWater[key]
				if seen && value > previous && o.Event != "INITED" && o.Event != "REDUCE" {
					o.Progress = true
				}
				if !seen || value > previous {
					p.highWater[key] = value
				}
			}
		}
		return o, true
	}
	if _, path, ok := strings.Cut(line, "Test unit written to "); ok && strings.TrimSpace(path) != "" {
		path = strings.TrimSpace(path)
		if !filepath.IsAbs(path) {
			path = filepath.Join(p.workDir, path)
		}
		o.Event = "artifact"
		o.Finding = &watchdog.Finding{Kind: "artifact", Artifact: path}
		return o, true
	}
	if strings.Contains(line, "ERROR: libFuzzer:") ||
		strings.Contains(line, "ERROR: AddressSanitizer:") ||
		strings.Contains(line, "ERROR: LeakSanitizer:") ||
		strings.Contains(line, "ERROR: UndefinedBehaviorSanitizer:") ||
		strings.Contains(line, "WARNING: MemorySanitizer:") ||
		strings.Contains(line, "WARNING: ThreadSanitizer:") ||
		strings.Contains(line, "runtime error:") {
		kind := "crash"
		switch {
		case strings.Contains(line, "out-of-memory"):
			kind = "out_of_memory"
		case strings.Contains(line, "timeout"):
			kind = "timeout"
		case strings.Contains(line, "LeakSanitizer"):
			kind = "leak"
		case strings.Contains(line, "Sanitizer"):
			kind = "sanitizer"
		}
		o.Event = "finding"
		o.Finding = &watchdog.Finding{Kind: kind, Message: line}
		return o, true
	}
	return o, false
}

func parseSize(token string, unitless float64) (float64, bool) {
	end := 0
	for end < len(token) && token[end] >= '0' && token[end] <= '9' {
		end++
	}
	value, err := strconv.ParseUint(token[:end], 10, 64)
	if err != nil {
		return 0, false
	}
	multipliers := map[string]float64{"": unitless, "b": 1, "kb": 1024, "mb": 1024 * 1024, "gb": 1024 * 1024 * 1024, "tb": 1024 * 1024 * 1024 * 1024}
	multiplier, ok := multipliers[strings.ToLower(token[end:])]
	return float64(value) * multiplier, ok
}
