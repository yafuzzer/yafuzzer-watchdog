//go:build linux

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/yafuzzer/yafuzzer-watchdog/internal/watchdog"
)

func report(w io.Writer, result watchdog.RunResult) error {
	var b strings.Builder
	stats := result.Statistics
	fmt.Fprintln(&b, "Fuzzing session result")
	fmt.Fprintf(&b, "Engine:             %s\nStop reason:        %s\nOutcome:            %s\n", result.Engine, result.Reason, result.Outcome)
	fmt.Fprintf(&b, "Elapsed time:       %s\nActive fuzzing time: %s\n", stats.ElapsedTime.Round(time.Millisecond), stats.ActiveTime.Round(time.Millisecond))
	fmt.Fprintf(&b, "Attempts:           %d\nRestarts:           %d\nTarget errors:      %d\n", stats.Attempts, stats.Restarts, stats.TargetErrors)
	var kinds []string
	for kind := range stats.ErrorsByKind {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		fmt.Fprintf(&b, "  %-18s%d\n", kind+":", stats.ErrorsByKind[kind])
	}
	metric := func(label, key string) {
		if value, ok := stats.Metrics[key]; ok {
			fmt.Fprintf(&b, "%-20s%g\n", label+":", value)
		} else {
			fmt.Fprintf(&b, "%-20sn/a\n", label+":")
		}
	}
	metric("Known executions", "executions")
	metric("Maximum coverage", "libfuzzer.coverage")
	metric("Maximum features", "libfuzzer.features")
	metric("Corpus entries", "corpus_entries")
	metric("Corpus bytes", "corpus_bytes")
	peak, exists := stats.Metrics["peak_rss_bytes"]
	if rss, ok := stats.Metrics["rss_bytes"]; ok && (!exists || rss > peak) {
		peak, exists = rss, true
	}
	if exists {
		fmt.Fprintf(&b, "Peak RSS bytes:     %g\n", peak)
	} else {
		fmt.Fprintln(&b, "Peak RSS bytes:     n/a")
	}
	if result.Exit.Code != nil {
		fmt.Fprintf(&b, "Last process code:  %d\n", *result.Exit.Code)
	}
	if result.Exit.Signal != "" {
		fmt.Fprintf(&b, "Last process signal: %s\n", result.Exit.Signal)
	}
	if result.Error != "" {
		fmt.Fprintf(&b, "Watchdog error:     %s\n", result.Error)
	}
	fmt.Fprintf(&b, "Corpus:             %s\nArtifacts:          %s\nJournal:            %s\nResult:             %s\n", result.OutputDir, result.ArtifactsDir, result.Files.Log, result.Files.Result)
	n, err := io.WriteString(w, b.String())
	if err == nil && n != b.Len() {
		return io.ErrShortWrite
	}
	return err
}
