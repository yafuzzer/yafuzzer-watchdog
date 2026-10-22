# Yafuzzer watchdog

A component of the **Yafuzzer** fuzzing system that provides a unified interface for controlling different fuzzing tools and monitoring local fuzzing processes.

## Description

**Yafuzzer watchdog** runs inside a container alongside the fuzzer. It launches the fuzzing process, monitors progress, collects metrics and diagnostics, applies stop conditions, and saves the results with the reason the session ended.

One watchdog invocation is a **session**. A session can contain one fuzzing process or several consecutive attempts when automatic restarts are enabled. It can operate independently of an external controller.

## Compatibility

The current version targets Linux and runs one fuzzing process at a time.

| Fuzzer | Support status |
| -------- | ---------------- |
| libFuzzer | supported (single process) |
| AFL++ | planned |
| Go fuzz | planned |

Controller integration is planned. The watchdog currently saves results locally and makes no network requests.

## Build

Requires Linux and Go 1.22 or later. The watchdog uses only the Go standard library.

```sh
go build -o bin/yafwd ./cmd/yafwd
./bin/yafwd --help
```

The target must already be compiled with libFuzzer. The watchdog does not build targets.

## Usage

```sh
./bin/yafwd \
  --engine libfuzzer \
  --input ./seeds \
  --output ./findings \
  --artifacts ./artifacts \
  --fuzzing-timeout 30m \
  --no-progress-timeout 5m \
  --restart on-crash \
  -- ./my_fuzzer -max_len=4096
```

`--engine` and the `--` separator are required. Everything after the separator is an executable and its arguments, passed directly without a shell. Quote paths and arguments containing spaces as usual. The fuzzer inherits the directory from which you launch watchdog; relative paths are resolved from that directory. Use `cd` before launching it to choose another working directory.

| Option | Default | Purpose |
| -------- | --------- | --------- |
| `-e`, `--engine` | required | Fuzzing engine; currently `libfuzzer` |
| `-i`, `--input` | not set | Optional existing seed corpus directory |
| `-o`, `--output` | `./findings` | Writable corpus directory; created if needed |
| `-a`, `--artifacts` | `./artifacts` | Error artifact directory; created if needed |
| `--runs-dir` | `./yafwd-runs` | Parent directory for session records |
| `--fuzzing-timeout` | `0` | Maximum total active fuzzing time across attempts |
| `--no-progress-timeout` | `0` | Maximum active time without new coverage across attempts |
| `--shutdown-timeout` | `5s` | Time allowed for a process to finish after a stop request |
| `--restart` | `never` | Restart policy: `never` or `on-crash` |

### Duration values

A number without a unit means **seconds**: `60` equals `60s`, and `1.5` equals `1.5s`. Units and combinations are also accepted, such as `500ms`, `5m`, `1h30m` and `2h`.

Zero disables either fuzzing limit. The shutdown timeout must be positive. Negative durations are rejected.

### Corpora and artifacts

The driver supplies the output directory as libFuzzer's first corpus directory, followed by the optional input directory. New interesting inputs are saved in `--output`. Despite its default name `findings`, this directory is the generated corpus; crash and other error artifacts go to `--artifacts`.

When `--input` is omitted, no separate seed corpus is added. Existing samples in `--output` remain available to libFuzzer, including after a restart. The watchdog reuses corpora without deleting samples. Input, output, artifacts and session-record directories must not overlap, including through symlinks.

Additional libFuzzer arguments must use `-name=value` syntax. The driver supplies `-artifact_prefix` and enables `-print_final_stats=1` unless explicitly configured. Conflicting artifact paths are rejected before launch.

Parallel modes (`-jobs`, `-workers`, `-fork` with nonzero values), merge and crash-minimization modes are unsupported. Options that suppress stderr or statistics required for monitoring are rejected. Use watchdog's `--fuzzing-timeout` and `--no-progress-timeout` instead of libFuzzer's `-max_total_time` and `-stale_corpus_timeout`.

### Progress and active time

Increases in libFuzzer's coverage (`cov`) or feature count (`ft`) count as progress. Initial statistics establish a baseline; corpus reductions and execution activity alone do not reset the no-progress timer. The maximum observed coverage is retained between attempts, so rediscovering old coverage after a restart does not count as progress.

Both fuzzing limits count **only the time that the fuzzing processes are running**, including their initialization. Their accumulated time is preserved between attempts. Preparation, post-exit processing, draining output and saving records between attempts do not consume these limits. For example, two seconds of fuzzing, ten seconds of processing and three more seconds of fuzzing count as five seconds of active time.

The no-progress timer starts with the first process and resets when new coverage is observed. Both limits work even when the fuzzer produces no output. The report records total elapsed time separately from active fuzzing time.

### Restarts

- `--restart never`: finish the session when the fuzzer exits. This is the default.
- `--restart on-crash`: restart after a recognized crash, sanitizer error, single-test timeout or out-of-memory error.

The watchdog restarts only after the process has exited and its output and remaining child processes have been handled. The next attempt starts immediately after that work; watchdog adds no delay or backoff. There is no separate restart-count limit. Both fuzzing time budgets continue from the previous attempt.

Successful completion and an unclassified unsuccessful exit end the session. Startup, monitoring and storage errors also end it. A diagnostic from a process that is still running does not itself trigger a restart.

### Stopping

When a fuzzing limit is reached, watchdog asks the fuzzer and its child processes to finish. It also forwards `Ctrl+C` (`SIGINT`) and termination requests (`SIGTERM`) to that process group.

After the request, `--shutdown-timeout` gives the processes time to finish voluntarily. If they finish sooner, watchdog continues immediately. Processes that are still running when this period expires are forcefully terminated with `SIGKILL`.

The shutdown timeout uses ordinary elapsed time. After stopping, watchdog reads the remaining output and saves the final result. Therefore session completion can take longer than the configured fuzzing timeout. Targets must remain in the process group created for them; detached processes are outside this mechanism.

## Session records

Each session creates a unique directory beneath `--runs-dir`:

```text
yafwd-runs/<timestamp>-<unique suffix>/
    config.json       Effective settings and prepared command
    run.log           Fuzzer stdout, stderr and watchdog messages
    metrics.jsonl     Timestamped observations with attempt numbers
    result.json       Session result and aggregate statistics
```

Every watchdog message in `run.log` starts with `[watchdog]`. Fuzzer output is preserved as received, with a newline inserted when switching sources midway through an unfinished line. Entries are serialized in the order watchdog receives them; the driver still reads stdout and stderr separately. Existing records from earlier versions are left untouched.

`result.json` contains the stop reason, last process exit status, paths and statistics. It does not duplicate individual error reports. Statistics include elapsed and active time, attempts, restarts, erroneous attempts by type, known executions, maximum observed coverage, latest corpus state and peak reported memory usage.

Each erroneous attempt is counted once, even when it produces several diagnostic lines and an artifact. These counts describe attempts, not unique bugs. Execution totals sum the last known counter from each attempt; if a process exits before reporting its final counter, some executions may be unobserved. Unavailable metrics remain absent. Durations in JSON fields ending in `_ns` are nanoseconds.

Detailed diagnostics remain in `run.log`, structured observations remain in `metrics.jsonl`, and reproducer files remain in `--artifacts`. Output is written during the run. Logs and metrics are synced and closed before `result.json` is published through an atomic rename. If storage fails, watchdog stops the session and attempts to save the error. A persistent filesystem failure or abrupt termination can prevent a final result from being written.

On completion, stdout contains a formatted text report, for example:

```text
Fuzzing session result
Engine:             libfuzzer
Stop reason:        fuzzing_timeout
Outcome:            stopped
Elapsed time:       30m0.4s
Active fuzzing time: 30m0s
Attempts:           4
Restarts:           3
Target errors:      3
...
Journal:            /work/yafwd-runs/<session>/run.log
Result:             /work/yafwd-runs/<session>/result.json
```

The session directory and command-line errors are printed to stderr with the `[watchdog]` prefix. The target's output is kept in the journal.

| Exit code | Meaning |
| ----------- | --------- |
| `0` | Successful completion, or either fuzzing limit was reached |
| `1` | The session ended on a target error or an unclassified unsuccessful process exit |
| `2` | Invalid configuration or a watchdog error |
| `130` | Interrupted by `SIGINT` |
| `143` | Interrupted by `SIGTERM` |

Errors in previous attempts do not change exit code `0` when the session subsequently completes successfully or reaches a fuzzing limit. Discovering new coverage does not affect the exit code.

Developer documentation is available in [docs/development.md](docs/development.md).
