# libgit2 benchmarks

This folder contains the individual benchmark tests for libgit2,
meant for understanding the performance characteristics of libgit2,
comparing your development code to the existing libgit2 code, or
comparing libgit2 to the git reference implementation.

## Running benchmark tests

Benchmark tests can be run in several different ways: running all
benchmarks, running one (or more) suite of benchmarks, or running a
single individual benchmark.  You can target either an individual
version of a CLI, or you can A/B test a baseline CLI against a test
CLI.

### Specifying the command-line interface to test

By default, the `git` in your path is benchmarked.  Use the
`-c` (or `--cli`) option to specify the command-line interface
to test.

Example: `libgit2_bench --cli git2_cli` will run the tests against
`git2_cli`.

### Running tests to compare two different implementations

You can compare a baseline command-line interface against a test
command-line interface using the `-b (or `--baseline-cli`) option.

Example: `libgit2_bench --baseline-cli git --cli git2_cli` will
run the tests against both `git` and `git2_cli`.

### Running individual benchmark tests

Similar to how a test suite or individual test is specified in
[clar](https://github.com/clar-test/clar), the `-s` (or `--suite`)
option may be used to specify the suite or individual test to run.
Like clar, the suite and test name are separated by `::`, and like
clar, this is a prefix match.

Examples:
* `libgit2_bench -shash_object` will run the tests in the
  `hash_object` suite.
* `libgit2_bench -shash_object::random_1kb` will run the
  `hash_object::random_1kb` test.
* `libgit2_bench -shash_object::random` will run all the tests that
  begin with `hash_object::random`.

## Writing benchmark tests

Benchmark tests are meant to be easy to write.  Each individual
benchmark is a shell script that allows it to do set up (eg, creating
or cloning a repository, creating temporary files, etc), then running
benchmarks, then teardown.

The `benchmark_helpers.sh` script provides many helpful utility
functions to allow for cross-platform benchmarking, as well as a
wrapper for `hyperfine` that is suited to testing libgit2.
Note that the helper script must be included first, at the beginning
of the benchmark test.

### Benchmark example

This simplistic example compares the speed of running the `git help`
command in the baseline CLI to the test CLI.

```bash
#!/bin/bash -e

# include the benchmark library
. "$(dirname "$0")/benchmark_helpers.sh"

# run the "help" command; this will benchmark `git2_cli help`
gitbench help
```

### Naming

The filename of the benchmark itself is important.  A benchmark's
filename should be the name of the benchmark suite, followed by two
underscores, followed by the name of the benchmark.  For example,
`hash-object__random_1kb` is the `random_1kb` test in the `hash-object`
suite.

### Options

You can set variables to pass options to the `gitbench` function.

* `REPOSITORY`  
  Set the `REPOSITORY` to the name of a test resource repository (in
  the `tests/resources` directory.  This repository will be copied into
  a sandbox location before test execution, and your test will run in
  this directory.  This is copied before the `PREPARE` script is run.
* `PREPARE`  
  A script to run before each invocation of the test is run.  This can
  set up data for the test that will _not_ be timed.  This script is run
  in bash on all platforms.
* `FLUSH_DISK_CACHE`  
  Set `FLUSH_DISK_CACHE=1` to flush the disk cache before each test.
  The disk cache will be flushed after the `PREPARE` script is run.
* `WARMUP`
  Set `WARMUP` to an integer to run the test multiple times before
  actually measuring the timing; useful for "warming up" a cache.

