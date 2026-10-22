// Package watchdog coordinates one fuzzing run without depending on a specific
// fuzzing engine or storage implementation.
package watchdog

import (
	"context"
	"io"
	"os"
	"time"
)

type RunConfig struct {
	Engine            string        `json:"engine"`
	Command           []string      `json:"command"`
	WorkDir           string        `json:"work_dir"`
	InputDir          string        `json:"input_dir,omitempty"`
	OutputDir         string        `json:"output_dir"`
	ArtifactsDir      string        `json:"artifacts_dir"`
	RunsDir           string        `json:"runs_dir"`
	FuzzingTimeout    time.Duration `json:"fuzzing_timeout_ns"`
	NoProgressTimeout time.Duration `json:"no_progress_timeout_ns"`
	ShutdownTimeout   time.Duration `json:"shutdown_timeout_ns"`
	Restart           RestartMode   `json:"restart"`
}

type RestartMode string

const (
	RestartNever   RestartMode = "never"
	RestartOnCrash RestartMode = "on-crash"
)

func DefaultConfig() RunConfig {
	return RunConfig{
		OutputDir:       "findings",
		ArtifactsDir:    "artifacts",
		RunsDir:         "yafwd-runs",
		ShutdownTimeout: 5 * time.Second,
		Restart:         RestartNever,
	}
}

type LaunchSpec struct {
	Executable  string   `json:"executable"`
	Args        []string `json:"args"`
	WorkDir     string   `json:"work_dir"`
	Env         []string `json:"env,omitempty"` // Additions to the inherited environment.
	Directories []string `json:"directories,omitempty"`
}

type Stream string

const (
	Stdout Stream = "stdout"
	Stderr Stream = "stderr"
)

// Sources are owned by Runner. Observe must drain both streams before returning.
// Drivers that also poll files can use Exited to take their final sample.
type Sources struct {
	Stdout       io.Reader
	Stderr       io.Reader
	WorkDir      string
	InputDir     string
	OutputDir    string
	ArtifactsDir string
	StartedAt    time.Time
	Exited       <-chan struct{}
}

type Finding struct {
	Kind     string `json:"kind"`
	Message  string `json:"message,omitempty"`
	Artifact string `json:"artifact,omitempty"`
}

// Missing metrics are absent, not zero. Engine-specific keys are namespaced,
// e.g. libfuzzer.coverage and libfuzzer.features.
type Observation struct {
	Attempt  int                `json:"attempt"`
	At       time.Time          `json:"at"`
	Engine   string             `json:"engine"`
	Event    string             `json:"event"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
	Progress bool               `json:"progress"`
	Finding  *Finding           `json:"finding,omitempty"`
}

type ExitStatus struct {
	Code   *int   `json:"code,omitempty"` // nil when the process never started.
	Signal string `json:"signal,omitempty"`
}

type Outcome string

const (
	OutcomeCompleted   Outcome = "completed"
	OutcomeTargetError Outcome = "target_error"
	OutcomeFailed      Outcome = "failed"
	OutcomeSignaled    Outcome = "signaled"
	OutcomeStopped     Outcome = "stopped"
)

type StopReason string

const (
	ReasonProcessExited  StopReason = "process_exited"
	ReasonFuzzingTimeout StopReason = "fuzzing_timeout"
	ReasonNoProgress     StopReason = "no_progress"
	ReasonInterrupted    StopReason = "interrupted"
	ReasonStartFailed    StopReason = "start_failed"
	ReasonMonitorFailed  StopReason = "monitor_failed"
	ReasonStorageFailed  StopReason = "storage_failed"
)

type RunFiles struct {
	Directory string `json:"directory"`
	Config    string `json:"config"`
	Log       string `json:"log"`
	Metrics   string `json:"metrics"`
	Result    string `json:"result"`
}

type RunResult struct {
	Engine       string     `json:"engine"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      time.Time  `json:"ended_at"`
	Reason       StopReason `json:"reason"`
	Exit         ExitStatus `json:"exit"`
	Outcome      Outcome    `json:"outcome"`
	StopSignal   string     `json:"stop_signal,omitempty"`
	Forced       bool       `json:"forced"`
	InputDir     string     `json:"input_dir,omitempty"`
	OutputDir    string     `json:"output_dir"`
	ArtifactsDir string     `json:"artifacts_dir"`
	Files        RunFiles   `json:"files"`
	Statistics   Statistics `json:"statistics"`
	Error        string     `json:"error,omitempty"`
}

type Statistics struct {
	ElapsedTime  time.Duration      `json:"elapsed_time_ns"`
	ActiveTime   time.Duration      `json:"active_time_ns"`
	Attempts     int                `json:"attempts"`
	Restarts     int                `json:"restarts"`
	TargetErrors int                `json:"target_errors"`
	ErrorsByKind map[string]int     `json:"errors_by_kind,omitempty"`
	Metrics      map[string]float64 `json:"metrics,omitempty"`
}

// Evidence is bounded by the engine's error categories, not its diagnostic volume.
type AttemptEvidence struct {
	Kinds    map[string]bool
	Artifact bool
}

type AttemptOutcome struct {
	Outcome   Outcome
	ErrorKind string
}

type MetricRule string

const (
	MetricSum  MetricRule = "sum" // Add the last known value from each attempt.
	MetricMax  MetricRule = "max"
	MetricLast MetricRule = "last"
)

// Prepare begins a session. Observe is called sequentially for its attempts and
// preserves session-wide progress. emit is serial; Observe joins all its work.
type Driver interface {
	Prepare(RunConfig) (LaunchSpec, error)
	Observe(context.Context, Sources, func(Observation) error) error
	Interpret(ExitStatus, AttemptEvidence) AttemptOutcome
	MetricRules() map[string]MetricRule
}

// Store accepts concurrent WriteOutput calls. All other calls are serialized by
// Runner, and Finish is called only after Observe has returned.
type Store interface {
	Begin(RunConfig, LaunchSpec, time.Time) (RunFiles, error)
	WriteOutput(Stream, []byte) error
	Log(string) error
	Append(Observation) error
	Finish(RunResult) error
}

// SignalError is a cancellation cause that preserves the original OS signal.
type SignalError struct{ Signal os.Signal }

func (e *SignalError) Error() string { return "received " + e.Signal.String() }
