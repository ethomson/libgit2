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

### Running individual benchmark tests

Similar to how a test suite or individual test is specified in
[clar](https://github.com/clar-test/clar), the `-s` (or `--suite`)
flag may be used to specify the suite or individual test to run.
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
. $(dirname $0)/benchmark_helpers.sh

# run the "help" command; this will benchmark `git2_cli help`
gitbench help
```

### Naming

The filename of the benchmark itself is important.  A benchmark's
filename should be the name of the benchmark suite, followed by two
underscores, followed by the name of the benchmark.  For example,
`hash-object__random_1kb` is the `random_1kb` test in the `hash-object`
suite.
