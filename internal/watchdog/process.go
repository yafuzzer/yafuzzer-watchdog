//go:build linux

package watchdog

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type processExit struct {
	status ExitStatus
	err    error
	at     time.Time
}

type process struct {
	pid       int
	stdout    *os.File
	stderr    *os.File
	done      <-chan struct{}
	startedAt time.Time
	exit      processExit // Published by closing done; read only after done is closed.
}

func startProcess(spec LaunchSpec) (*process, error) {
	stdout, outWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderr, errWriter, err := os.Pipe()
	if err != nil {
		stdout.Close()
		outWriter.Close()
		return nil, err
	}
	defer outWriter.Close()
	defer errWriter.Close()
	cmd := exec.Command(spec.Executable, spec.Args...)
	cmd.Dir = spec.WorkDir
	cmd.Env = append(os.Environ(), spec.Env...)
	cmd.Stdout = outWriter
	cmd.Stderr = errWriter
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return nil, err
	}
	done := make(chan struct{})
	p := &process{pid: cmd.Process.Pid, stdout: stdout, stderr: stderr, done: done, startedAt: time.Now()}
	go func() {
		err := cmd.Wait()
		at := time.Now()
		var status ExitStatus
		if cmd.ProcessState != nil {
			code := cmd.ProcessState.ExitCode()
			status.Code = &code
			if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				status.Signal = signalName(ws.Signal())
			}
		}
		// An ExitError describes the fuzzer's result, not a watchdog failure.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			err = nil
		}
		p.exit = processExit{status: status, err: err, at: at}
		close(done)
	}()
	return p, nil
}

func (p *process) snapshot() (processExit, bool) {
	select {
	case <-p.done:
		return p.exit, true
	default:
		return processExit{}, false
	}
}

func (p *process) signal(signal os.Signal) error {
	sig, ok := signal.(syscall.Signal)
	if !ok {
		sig = syscall.SIGTERM
	}
	err := syscall.Kill(-p.pid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (p *process) groupAlive() bool {
	err := syscall.Kill(-p.pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func (p *process) closeOutput() {
	p.stdout.Close()
	p.stderr.Close()
}

func signalName(signal os.Signal) string {
	switch signal {
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGSEGV:
		return "SIGSEGV"
	case syscall.SIGILL:
		return "SIGILL"
	case syscall.SIGFPE:
		return "SIGFPE"
	case syscall.SIGBUS:
		return "SIGBUS"
	case syscall.SIGTRAP:
		return "SIGTRAP"
	default:
		if sig, ok := signal.(syscall.Signal); ok {
			return fmt.Sprintf("SIG%d", sig)
		}
		return signal.String()
	}
}
