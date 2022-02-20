# variables that benchmark tests can set
#

set -eo pipefail

# this test should flush the disk cache before runs
FLUSH_DISK_CACHE=0

# this test should run the given command in preparation of the tests
# (note that this overrides `FLUSH_DISK_CACHE`)
PREPARE=

# this test should run warmups
WARMUP=0

#
# command-line parsing
#

usage() { echo "usage: $(basename "$0") [--cli <path>] [--baseline-cli <path>] [--output-style <style>] [--json <path>]"; }

NEXT=
BASELINE_CLI=
TEST_CLI="git"
JSON=
SHOW_OUTPUT=

if [ "$CI" != "" ]; then
	OUTPUT_STYLE="--style color"
else
	OUTPUT_STYLE="--style auto"
fi

for a in "$@"; do
	if [ "${NEXT}" = "cli" ]; then
		TEST_CLI="${a}"
		NEXT=
	elif [ "${NEXT}" = "baseline-cli" ]; then
		BASELINE_CLI="${a}"
		NEXT=
	elif [ "${NEXT}" = "output-style" ]; then
		OUTPUT_STYLE="${a}"
		NEXT=
	elif [ "${NEXT}" = "json" ]; then
		JSON="${a}"
		NEXT=
	elif [ "${a}" = "-c" -o "${a}" = "--cli" ]; then
		NEXT="cli"
	elif [[ "${a}" == "-c"* ]]; then
		TEST_CLI=$(echo "${a}" | sed -e "s/^-c//")
	elif [ "${a}" = "-b" -o "${a}" = "--baseline-cli" ]; then
		NEXT="baseline-cli"
	elif [[ "${a}" == "-b"* ]]; then
		BASELINE_CLI=$(echo "${a}" | sed -e "s/^-b//")
	elif [ "${a}" == "--output-style" ]; then
		NEXT="output-style"
	elif [ "${a}" = "-j" -o "${a}" = "--json" ]; then
		NEXT="json"
	elif [[ "${a}" == "-j"* ]]; then
		JSON="${a}"
	elif [ "${a}" = "--show-output" ]; then
		SHOW_OUTPUT="--show-output"
		OUTPUT_STYLE=
	fi
done

if [ "${NEXT}" != "" ]; then
        usage 1>&2
        exit 1
fi

NAME=$(basename $0)

create_rand() {
	KILOBYTES=${1:=1}
	FILENAME=$(mktemp)

	if [[ "$(uname -s)" == "MINGW"* ]]; then
		DEVICE="/dev/random"
	else
		DEVICE="/dev/urandom"
	fi

	dd if="${DEVICE}" of="${FILENAME}" bs=1k count="${KILOBYTES}" >/dev/null 2>&1

	if [[ "$(uname -s)" == "MINGW"* ]]; then
		cygpath -w "${FILENAME}"
	else
		echo "${FILENAME}"
	fi
}

flush_cache() {
	if [ "$(uname -s)" = "Darwin" ]; then
		echo "sync && sudo purge"
	elif [ "$(uname -s)" = "Linux" ]; then
		echo "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null"
	elif [[ "$(uname -s)" == MINGW* ]]; then
		echo "PurgeStandbyList"
	fi
}

gitbench() {
	if [ "$1" = "" ]; then
		echo "usage: gitbench command..." 1>&2
		exit 1
	fi

	if [ "$FLUSH_DISK_CACHE" = "1" ]; then
		PREPARE=${PREPARE:=$(flush_cache)}
	fi

	if [ "$JSON" != "" ]; then
		JSON_ARG="--export-json ${JSON}"
	fi

	if [ "${BASELINE_CLI}" != "" ]; then
		hyperfine --prepare "${PREPARE}" --warmup "${WARMUP}" ${OUTPUT_STYLE} ${SHOW_OUTPUT} ${JSON_ARG} "${BASELINE_CLI} ${1}" "${TEST_CLI} ${1}"
	else
		hyperfine --prepare "${PREPARE}" --warmup "${WARMUP}" ${OUTPUT_STYLE} ${SHOW_OUTPUT} ${JSON_ARG} "${TEST_CLI} ${1}"
	fi
}
