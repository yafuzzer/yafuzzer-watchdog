//go:build linux

package watchdog

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

type attemptResult struct {
	started bool
	exit    ExitStatus
	outcome AttemptOutcome
	metrics map[string]float64
	forced  bool
}

func (s *session) runAttempt(ctx context.Context, spec LaunchSpec, number int) attemptResult {
	a := attemptResult{metrics: make(map[string]float64)}
	if !s.log("Starting attempt %d", number) {
		return a
	}
	if ctx.Err() != nil {
		s.interrupt(ctx)
		return a
	}
	p, err := startProcess(spec)
	if err != nil {
		s.fail(ReasonStartFailed, fmt.Errorf("start fuzzer: %w", err))
		return a
	}
	a.started = true
	s.result.Statistics.Attempts++
	s.result.Statistics.Restarts = s.result.Statistics.Attempts - 1
	s.policy.resume(p.startedAt)
	defer p.closeOutput()
	observeCtx, cancelObserve := context.WithCancel(context.Background())
	defer cancelObserve()
	observations := make(chan Observation, 64)
	monitorDone := make(chan error, 1)
	outputErrors := make(chan error, 1)
	go func() {
		err := s.runner.Driver.Observe(observeCtx, Sources{
			Stdout:  io.TeeReader(p.stdout, outputWriter{s.runner.Store, Stdout, outputErrors, &s.storageFailed}),
			Stderr:  io.TeeReader(p.stderr, outputWriter{s.runner.Store, Stderr, outputErrors, &s.storageFailed}),
			WorkDir: spec.WorkDir, InputDir: s.config.InputDir, OutputDir: s.config.OutputDir,
			ArtifactsDir: s.config.ArtifactsDir, StartedAt: p.startedAt, Exited: p.done,
		}, func(o Observation) error {
			select {
			case observations <- o:
				return nil
			case <-observeCtx.Done():
				return observeCtx.Err()
			}
		})
		close(observations)
		monitorDone <- err
	}()
	policyTimer := time.NewTimer(time.Hour)
	policyTimer.Stop()
	defer policyTimer.Stop()
	var policyC <-chan time.Time
	resetPolicy := func() {
		if !policyTimer.Stop() {
			select {
			case <-policyTimer.C:
			default:
			}
		}
		if remaining, enabled := s.policy.remaining(time.Now()); enabled {
			policyTimer.Reset(remaining)
			policyC = policyTimer.C
		} else {
			policyC = nil
		}
	}
	resetPolicy()
	var graceTimer, drainTimer *time.Timer
	var graceC, drainC <-chan time.Time
	defer func() {
		if graceTimer != nil {
			graceTimer.Stop()
		}
		if drainTimer != nil {
			drainTimer.Stop()
		}
	}()
	startDrainTimer := func() {
		if drainTimer == nil {
			drainTimer = time.NewTimer(s.config.ShutdownTimeout)
			drainC = drainTimer.C
		}
	}
	stopping, exited, monitored, closedOutput := false, false, false, false
	stop := func(sig os.Signal) {
		if stopping {
			return
		}
		stopping, policyC = true, nil
		policyTimer.Stop()
		if err := p.signal(sig); err != nil {
			s.fail(ReasonMonitorFailed, fmt.Errorf("signal fuzzer group: %w", err))
		}
		graceTimer = time.NewTimer(s.config.ShutdownTimeout)
		graceC = graceTimer.C
		s.log("Stopping attempt %d with %s; shutdown timeout=%s", number, signalName(sig), s.config.ShutdownTimeout)
	}
	processDone := p.done
	syncExit := func() {
		if exited {
			return
		}
		exit, ready := p.snapshot()
		if !ready {
			return
		}
		// Use the time captured by Wait, not time spent draining or handling events.
		s.policy.pause(exit.at)
		a.exit, exited, processDone, policyC = exit.status, true, nil, nil
		policyTimer.Stop()
		if exit.err != nil {
			s.fail(ReasonMonitorFailed, fmt.Errorf("wait for fuzzer: %w", exit.err))
		}
		if !stopping && p.groupAlive() {
			stop(syscall.SIGTERM)
		}
		if !stopping {
			startDrainTimer()
		}
	}
	evidence := AttemptEvidence{Kinds: make(map[string]bool)}
	record := func(o Observation) {
		syncExit()
		o.Attempt = number
		for key, value := range o.Metrics {
			previous, exists := a.metrics[key]
			if s.rules[key] != MetricMax || !exists || value > previous {
				a.metrics[key] = value
			}
		}
		if o.Finding != nil {
			if o.Finding.Kind == "artifact" {
				evidence.Artifact = true
			} else {
				evidence.Kinds[o.Finding.Kind] = true
			}
		}
		s.policy.observe(o)
		if !s.storageFailed.Load() {
			if err := s.runner.Store.Append(o); err != nil {
				s.fail(ReasonStorageFailed, fmt.Errorf("write observation: %w", err))
				stop(syscall.SIGTERM)
			}
		}
		if !stopping && !exited {
			resetPolicy()
		}
	}
	ctxDone := ctx.Done()
	for {
		syncExit()
		if s.err != nil && !stopping {
			stop(syscall.SIGTERM)
		}
		if exited && monitored && observations == nil && (!stopping || a.forced || !p.groupAlive()) {
			break
		}
		select {
		case <-ctxDone:
			ctxDone = nil
			if s.err == nil && s.result.Reason == "" {
				s.interrupt(ctx)
			}
			stop(cancellationSignal(ctx))
		case <-policyC:
			syncExit()
			for pending := len(observations); pending > 0; pending-- {
				record(<-observations)
			}
			if stopping || exited {
				continue
			}
			if reason := s.policy.reason(time.Now()); reason != "" {
				s.result.Reason = reason
				s.log("Fuzzing limit reached: %s", reason)
				stop(syscall.SIGTERM)
			} else {
				resetPolicy()
			}
		case o, ok := <-observations:
			if !ok {
				observations = nil
				continue
			}
			record(o)
		case err := <-outputErrors:
			s.fail(ReasonStorageFailed, err)
			stop(syscall.SIGTERM)
		case err := <-monitorDone:
			monitored, monitorDone = true, nil
			if err != nil && !closedOutput {
				s.fail(ReasonMonitorFailed, fmt.Errorf("monitor fuzzer: %w", err))
				stop(syscall.SIGTERM)
			}
		case <-processDone:
			syncExit()
		case <-graceC:
			graceC = nil
			if p.groupAlive() {
				if err := p.signal(syscall.SIGKILL); err != nil {
					s.fail(ReasonMonitorFailed, fmt.Errorf("kill fuzzer group: %w", err))
				}
				a.forced = true
				s.log("Forcefully terminated attempt %d with SIGKILL", number)
			}
			startDrainTimer()
		case <-drainC:
			drainC = nil
			if !monitored {
				closedOutput = true
				cancelObserve()
				p.closeOutput()
				s.fail(ReasonMonitorFailed, fmt.Errorf("fuzzer output did not drain within %s after shutdown", s.config.ShutdownTimeout))
			}
		}
	}
	select {
	case err := <-outputErrors:
		s.fail(ReasonStorageFailed, err)
	default:
	}
	a.outcome = s.runner.Driver.Interpret(a.exit, evidence)
	s.log("Attempt %d finished; outcome=%s error_kind=%s exit=%v signal=%s", number, a.outcome.Outcome, a.outcome.ErrorKind, exitDescription(a.exit), a.exit.Signal)
	return a
}

func exitDescription(exit ExitStatus) string {
	if exit.Code == nil {
		return "n/a"
	}
	return fmt.Sprint(*exit.Code)
}

type outputWriter struct {
	store  Store
	stream Stream
	errors chan<- error
	failed *atomic.Bool
}

func (w outputWriter) Write(data []byte) (int, error) {
	if !w.failed.Load() {
		if err := w.store.WriteOutput(w.stream, data); err != nil && w.failed.CompareAndSwap(false, true) {
			w.errors <- fmt.Errorf("write %s: %w", w.stream, err)
		}
	}
	// Drain pipes even after a disk error so the process group can terminate.
	return len(data), nil
}
