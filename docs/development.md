# Developer documentation

## Architecture

The repository is one Go module. The entry point wires implementations into the runtime; the runtime does not import the libFuzzer driver or file store.

```text
cmd/yafwd/                 CLI entry point, signals, text report, exit codes
internal/cli/              Argument parsing and duration syntax
internal/watchdog/         Sessions, attempts, process groups, policies and contracts
internal/driver/libfuzzer/  Command preparation, progress, diagnostics and metric rules
internal/storage/          Unified journal, observations and final records
```

`RunConfig` describes a session. Its internal working-directory field records the inherited directory and permits isolated runtime tests; there is no working-directory CLI flag.

`Runner.Run` prepares a driver and store once, then launches attempts sequentially. A driver implements:

- `Prepare`: validate engine-specific settings, create a launch specification and reset session progress state.
- `Observe`: consume both streams and emit observations serially. Calls are sequential within a session, and coverage maxima survive attempts. All goroutines must be joined before returning.
- `Interpret`: classify the last exit using bounded error-category evidence. The runtime does not retain diagnostic arrays.
- `MetricRules`: describe aggregation as the sum of each attempt's last value, a maximum, or the latest value.

Raw diagnostics and artifact notifications remain in the observation history. One classified target error is counted per attempt. The runtime chooses whether to restart using the classification, the restart mode, cancellation and remaining active budgets.

## Time accounting and process lifecycle

The process layer records successful startup and the time `Wait` observes exit. The policy maintains an active-time axis: resume at startup, freeze at the recorded exit, and resume at the next startup. Event-processing delays do not extend an attempt. Progress observations drained after exit are clamped to that attempt's end.

The fuzzing and no-progress budgets persist across attempts. Neither advances during inactive work. There is no restart sleep or backoff. The shutdown grace period and output-drain deadline are separate lifecycle operations measured in elapsed time; both currently use the configured shutdown duration.

Processes are started directly with `os/exec` in a new Linux process group. Explicit OS pipes let `Wait` finish independently of readers, so final output can be drained after the leader exits. Shutdown signals the group, escalates to `SIGKILL` after the grace period and bounds output draining. Remaining descendants in the group are cleaned up before another attempt starts. The container's init is responsible for reaping orphaned descendants.

## Persistence

`Store.Begin` creates a unique session directory. Concurrent stdout and stderr writes are serialized into `run.log`. Service messages use the same writer, with a `[watchdog]` prefix on every line. A source switch adds a newline if the previous write left an unfinished line. Stream separation is retained for parsing.

Each structured observation has an attempt number. The configuration record uses version 2. Configuration and result records are atomically renamed and their directory is synced. Existing session directories are not migrated or modified.

The result contains aggregate statistics and metadata, without individual findings. Sum rules use the final observed value per attempt rather than summing successive samples. Max rules retain high-water values, and last rules preserve the latest available sample. Missing metrics are not zero-filled. The text report is rendered independently of JSON persistence.

A future controller adapter can transmit saved records independently of fuzzing. Its protocol and delivery guarantees are deferred until that integration is implemented.

## Development

Requires Linux and Go 1.22 or later. No external Go dependencies are needed.

```sh
go build -o bin/yafwd ./cmd/yafwd
go test ./...
go test -race ./...
go vet ./...
```

The race check requires a C compiler. Runtime tests use the test executable as a subprocess fixture and require no libFuzzer installation. They cover:

- CLI boundaries, mandatory engine selection, duration formats and defaults;
- engine preparation, coverage high-water state and error classification;
- active budgets across attempts, inactive processing and immediate restarts;
- silent targets, signals during and between attempts, graceful shutdown and group cleanup;
- stream merging, partial lines, journal prefixes and storage failures;
- aggregate statistics, attempt-tagged observations, textual reports and exit codes.

Policy tests use explicit timestamps for deterministic accounting. Subprocess tests exercise real pipe and signal behavior. For a manual libFuzzer check, compile a target with Clang's `-fsanitize=fuzzer`, then exercise finite runs, a reproducible crash, restart-to-limit behavior and `SIGINT`/`SIGTERM` delivery. Keep generated fixtures outside the repository.
