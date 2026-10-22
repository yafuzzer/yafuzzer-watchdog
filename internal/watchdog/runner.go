//go:build linux

package watchdog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

type Runner struct {
	Driver Driver
	Store  Store
}

type session struct {
	runner        Runner
	config        RunConfig
	result        RunResult
	policy        policy
	rules         map[string]MetricRule
	err           error
	storageFailed atomic.Bool
}

func (r Runner) Run(ctx context.Context, config RunConfig) (RunResult, error) {
	if r.Driver == nil || r.Store == nil {
		return RunResult{}, fmt.Errorf("driver and store are required")
	}
	c, err := config.Resolve()
	if err != nil {
		return RunResult{}, err
	}
	spec, err := r.Driver.Prepare(c)
	if err != nil {
		return RunResult{}, fmt.Errorf("prepare %s: %w", c.Engine, err)
	}
	s := session{
		runner: r, config: c, policy: newPolicy(c), rules: r.Driver.MetricRules(),
		result: RunResult{
			Engine: c.Engine, StartedAt: time.Now(), Outcome: OutcomeFailed,
			InputDir: c.InputDir, OutputDir: c.OutputDir, ArtifactsDir: c.ArtifactsDir,
			Statistics: Statistics{Metrics: make(map[string]float64), ErrorsByKind: make(map[string]int)},
		},
	}
	s.result.Files, err = r.Store.Begin(c, spec, s.result.StartedAt)
	if err != nil {
		s.fail(ReasonStorageFailed, fmt.Errorf("create session record: %w", err))
		s.result.EndedAt = time.Now()
		return s.result, s.err
	}
	if !s.log("Session started; engine=%s restart=%s", c.Engine, c.Restart) {
		return s.finish()
	}
	for _, dir := range spec.Directories {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			s.fail(ReasonStartFailed, fmt.Errorf("create fuzzer directory: %w", err))
			return s.finish()
		}
	}
	for {
		if ctx.Err() != nil {
			s.interrupt(ctx)
			break
		}
		if reason := s.policy.reason(time.Now()); reason != "" {
			s.result.Reason = reason
			break
		}
		attempt := s.runAttempt(ctx, spec, s.result.Statistics.Attempts+1)
		s.merge(attempt)
		if s.err != nil || s.result.Reason != "" {
			break
		}
		if ctx.Err() != nil {
			s.interrupt(ctx)
			break
		}
		// The process can have exited before the event loop handled a policy timer.
		if reason := s.policy.reason(time.Now()); reason != "" {
			s.result.Reason = reason
			break
		}
		if c.Restart == RestartOnCrash && attempt.outcome.Outcome == OutcomeTargetError {
			if !s.log("Restarting after %s; next attempt=%d", attempt.outcome.ErrorKind, s.result.Statistics.Attempts+1) {
				break
			}
			continue // No delay: inactive work does not consume either fuzzing budget.
		}
		s.result.Reason = ReasonProcessExited
		break
	}
	return s.finish()
}

func (s *session) fail(reason StopReason, err error) {
	s.err = errors.Join(s.err, err)
	s.result.Reason, s.result.Error = reason, s.err.Error()
	if reason == ReasonStorageFailed {
		s.storageFailed.Store(true)
	} else if !s.storageFailed.Load() {
		s.log("Error: %v", err)
	}
}

func (s *session) log(format string, args ...any) bool {
	if s.storageFailed.Load() {
		return false
	}
	if err := s.runner.Store.Log(fmt.Sprintf(format, args...)); err != nil {
		s.fail(ReasonStorageFailed, fmt.Errorf("write watchdog journal: %w", err))
		return false
	}
	return true
}

func (s *session) interrupt(ctx context.Context) {
	s.result.Reason, s.result.StopSignal = ReasonInterrupted, signalName(cancellationSignal(ctx))
}

func (s *session) merge(a attemptResult) {
	if !a.started {
		return
	}
	s.result.Exit, s.result.Outcome = a.exit, a.outcome.Outcome
	s.result.Forced = s.result.Forced || a.forced
	if a.outcome.Outcome == OutcomeTargetError {
		s.result.Statistics.TargetErrors++
		s.result.Statistics.ErrorsByKind[a.outcome.ErrorKind]++
	}
	for key, value := range a.metrics {
		previous, exists := s.result.Statistics.Metrics[key]
		switch s.rules[key] {
		case MetricSum:
			s.result.Statistics.Metrics[key] = previous + value
		case MetricMax:
			if !exists || value > previous {
				s.result.Statistics.Metrics[key] = value
			}
		default:
			s.result.Statistics.Metrics[key] = value
		}
	}
}

func (s *session) finish() (RunResult, error) {
	switch s.result.Reason {
	case ReasonFuzzingTimeout, ReasonNoProgress, ReasonInterrupted:
		s.result.Outcome = OutcomeStopped
	}
	s.log("Session finished; reason=%s attempts=%d target_errors=%d", s.result.Reason, s.result.Statistics.Attempts, s.result.Statistics.TargetErrors)
	s.result.EndedAt = time.Now()
	s.result.Statistics.ElapsedTime = s.result.EndedAt.Sub(s.result.StartedAt)
	s.result.Statistics.ActiveTime = s.policy.active(s.result.EndedAt)
	if err := s.runner.Store.Finish(s.result); err != nil {
		s.fail(ReasonStorageFailed, fmt.Errorf("finalize session: %w", err))
	}
	return s.result, s.err
}

func cancellationSignal(ctx context.Context) os.Signal {
	var signalErr *SignalError
	if errors.As(context.Cause(ctx), &signalErr) {
		return signalErr.Signal
	}
	return syscall.SIGTERM
}
