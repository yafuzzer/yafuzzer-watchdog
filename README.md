# Yafuzzer watchdog

A component of the **Yafuzzer** fuzzing system for monitoring local fuzzing processes. It tracks test execution time and monitors fuzzing status.

## Description

**Yafuzzer watchdog** is a standalone utility that provides a unified interface for controlling different fuzzing tools and monitoring fuzzing runs. It runs inside a container alongside the fuzzer, starts the fuzzing process, tracks its state and progress, collects metrics and logs, applies configured stop conditions, and saves the results along with the reason the run ended.

The watchdog is designed for long-running, unattended fuzzing runs. For example, fuzzing can be stopped after a specified amount of time or when no progress has been made for a configured interval. The metrics and available stop conditions depend on the fuzzing engine being used.

The utility can be used as part of the Yafuzzer system or run independently. In standalone mode, fuzzing monitoring and stop conditions run locally and do not depend on the availability of an external control application.

## Compatibility

The table below shows the current support status for fuzzing systems:

| Fuzzer    | Support status |
|-----------|----------------|
| libFuzzer | in progress 🔄 |
| AFL++     | planned ❌     |
| Go fuzz   | planned ❌     |

## Usage

```
Usage: yafwd [OPTIONS] -- FUZZING_COMMAND

Options:
    -e, --engine string     Set the fuzzing engine ("libfuzzer", "afl", "go")
    -i, --input path        Set the input directory containing the seed corpus
    -o, --output path       Set the output directory for the generated corpus
    -a, --artifacts path    Set the output directory for fuzzing artifacts (crashes, hangs)
```
