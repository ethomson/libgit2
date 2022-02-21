#!/bin/bash

set -eo pipefail

#
# parse the command line
#

usage() { echo "usage: $(basename "$0") [--cli <path>] [--baseline-cli <path>] [--suite <suite>] [--json <path>] [--zip <path>] [--verbose]"; }

CLI="git"
BASELINE_CLI=
SUITE=
JSON_RESULT=
ZIP_RESULT=
OUTPUT_DIR=
VERBOSE=
NEXT=

for a in "$@"; do
	if [ "${NEXT}" = "cli" ]; then
		CLI="${a}"
		NEXT=
	elif [ "${NEXT}" = "baseline-cli" ]; then
		BASELINE_CLI="${a}"
		NEXT=
	elif [ "${NEXT}" = "suite" ]; then
		SUITE="${a}"
		NEXT=
	elif [ "${NEXT}" = "json" ]; then
		JSON_RESULT="${a}"
		NEXT=
	elif [ "${NEXT}" = "zip" ]; then
		ZIP_RESULT="${a}"
		NEXT=
	elif [ "${NEXT}" = "output-dir" ]; then
		OUTPUT_DIR="${a}"
		NEXT=
	elif [ "${a}" = "c" -o "${a}" = "--cli" ]; then
		NEXT="cli"
	elif [[ "${a}" == "-c"* ]]; then
		CLI=$(echo "${a}" | sed -e "s/^-c//")
	elif [ "${a}" = "b" -o "${a}" = "--baseline-cli" ]; then
		NEXT="baseline-cli"
	elif [[ "${a}" == "-b"* ]]; then
		BASELINE_CLI=$(echo "${a}" | sed -e "s/^-b//")
	elif [ "${a}" = "-s" -o "${a}" = "--suite" ]; then
		NEXT="suite"
	elif [[ "${a}" == "-s"* ]]; then
		SUITE=$(echo "${a}" | sed -e "s/^-s//")
	elif [ "${a}" = "-v" -o "${a}" == "--verbose" ]; then
		VERBOSE=1
	elif [ "${a}" = "-j" -o "${a}" == "--json" ]; then
		NEXT="json"
	elif [[ "${a}" == "-j"* ]]; then
		JSON_RESULT=$(echo "${a}" | sed -e "s/^-j//")
	elif [ "${a}" = "-z" -o "${a}" == "--zip" ]; then
		NEXT="zip"
	elif [[ "${a}" == "-z"* ]]; then
		ZIP_RESULT=$(echo "${a}" | sed -e "s/^-z//")
	elif [ "${a}" = "--output-dir" ]; then
		NEXT="output-dir"
	else
		usage 1>&2
		exit 1
	fi
done

if [ "${NEXT}" != "" ]; then
	usage 1>&2
	exit 1
fi

if [ "${OUTPUT_DIR}" = "" ]; then
	OUTPUT_DIR=${OUTPUT_DIR:="$(mktemp -d)"}
	CLEANUP_DIR=1
fi

#
# collect some information about the test environment
#

SYSTEM_OS=$(uname -s)
if [ "${SYSTEM_OS}" = "Darwin" ]; then SYSTEM_OS="macOS"; fi

SYSTEM_KERNEL=$(uname -v)

fullpath() {
	if [[ "$(uname -s)" == "MINGW"* && $(cygpath -u "${CLI}") == "/"* ]]; then
		echo "${CLI}"
	elif [[ "${CLI}" == "/"* ]]; then
		echo "${CLI}"
	else
		which "${CLI}"
	fi
}

CLI_NAME=$(basename "${CLI}")
CLI_PATH=$(fullpath "${CLI}")
CLI_VERSION=$("${CLI}" --version)

if [ "${BASELINE_CLI}" != "" ]; then
	if [[ "${BASELINE_CLI}" == "/"* ]]; then
		BASELINE_CLI_PATH="${BASELINE_CLI}"
	else
		BASELINE_CLI_PATH=$(which "${BASELINE_CLI}")
	fi

	BASELINE_CLI_NAME=$(basename "${BASELINE_CLI}")
	BASELINE_CLI_PATH=$(fullpath "${BASELINE_CLI}")
	BASELINE_CLI_VERSION=$("${BASELINE_CLI}" --version)
fi

#
# run the benchmarks
#

echo "##############################################################################"
if [ "${SUITE}" != "" ]; then
	SUITE_PREFIX=$(echo "${SUITE}" | sed -e "s/::/__/")
	echo "# Running ${SUITE} benchmarks"
else
	echo "# Running all benchmarks"
fi
echo "##############################################################################"
echo ""

if [ "${VERBOSE}" != "" ]; then
	echo "Test CLI: ${CLI}"

	if [ "${BASELINE_CLI}" != "" ]; then
		echo "Baseline CLI: ${BASELINE_CLI}"
	fi

	echo ""
fi

BENCHMARK_DIR=${BENCHMARK_DIR:=$(dirname "$0")}
ANY_FOUND=
ANY_FAILED=

indent() { sed "s/^/  /"; }
time_in_ms() { if [ $(uname -s) = "Darwin" ]; then date "+%s000"; else date "+%s%N" ; fi; }
humanize_secs() {
	if [ "$0" = "" ]; then
		return ""
	fi

	# bash doesn't do floating point arithmetic, and we can't rely on
	# bc being installed (it's not part of Git for Windows).  ick.
	perl -w <<EOF
use strict;
my @units = ( 's', 'ms', 'us', 'ns' );
my \$num = "${1}";
my \$cnt = 0;
while (\$num < 1 && \$cnt < \$#units) {
        \$num *= 1000;
        \$cnt++;
}
printf("%.2f %s\n", \$num, \$units[\$cnt]);
EOF
}

TIME_START=$(time_in_ms)

for TEST_PATH in "${BENCHMARK_DIR}"/*; do
	TEST_FILE=$(basename "${TEST_PATH}")

	if [ ! -f "${TEST_PATH}" -o ! -x "${TEST_PATH}" ]; then
		continue
	fi

	if [[ "${TEST_FILE}" != *"__"* ]]; then
		continue
	fi

	if [[ "${TEST_FILE}" != "${SUITE_PREFIX}"* ]]; then
		continue
	fi

	ANY_FOUND=1
	TEST_NAME=$(echo "${TEST_FILE}" | sed -e "s/__/::/")

	echo -n "# Benchmark: ${TEST_NAME}"
	if [ "${VERBOSE}" = "1" ]; then
		echo ""
	else
		echo -n ":  "
	fi

	OUTPUT_FILE="${OUTPUT_DIR}/${TEST_FILE}.out"
	JSON_FILE="${OUTPUT_DIR}/${TEST_FILE}.json"
	ERROR_FILE="${OUTPUT_DIR}/${TEST_FILE}.err"

	FAILED=
	${TEST_PATH} --cli "${CLI}" --baseline-cli "${BASELINE_CLI}" --json "${JSON_FILE}" >${OUTPUT_FILE} 2>${ERROR_FILE} || FAILED=1

	if [ "${FAILED}" = "1" ]; then
		if [ "${VERBOSE}" != "1" ]; then
			echo "failed!"
		fi

		indent < "${ERROR_FILE}"
		ANY_FAILED=1
		continue
	fi

	# in verbose mode, just print the hyperfine results; otherwise,
	# pull the useful information out of its json and summarize it
	if [ "${VERBOSE}" = "1" ]; then
		indent < "${OUTPUT_FILE}"
	else
		jq -r '[ .results[0].mean, .results[0].stddev, .results[1].mean, .results[1].stddev ] | @tsv' < "${JSON_FILE}" | while IFS=$'\t' read -r one_mean one_stddev two_mean two_stddev; do
			one_mean=$(humanize_secs "${one_mean}")
			one_stddev=$(humanize_secs "${one_stddev}")

			if [ "$?" != "0" ]; then exit 1; fi

			if [ "${two_mean}" != "" ]; then
				two_mean=$(humanize_secs "${two_mean}")
				two_stddev=$(humanize_secs "${two_stddev}")

				echo "${one_mean} ± ${one_stddev}  vs  ${two_mean} ± ${two_stddev}"
			else
				echo "${one_mean} ± ${one_stddev}"
			fi
		done
	fi

	# add our metadata to the hyperfine json result
	jq ". |= { \"name\": \"${TEST_NAME}\" } + ." < "${JSON_FILE}" > "${JSON_FILE}.new" && mv "${JSON_FILE}.new" "${JSON_FILE}"
done

TIME_END=$(time_in_ms)

if [ "$ANY_FOUND" != "1" ]; then
	echo ""
	echo "error: no benchmark suite \"${SUITE}\"."
	echo ""
	exit 1
fi

# combine all the individual benchmark results into a single json file
if [ "${JSON_RESULT}" != "" ]; then
	if [ "${VERBOSE}" = "1" ]; then
		echo ""
		echo "# Writing JSON results: ${JSON_RESULT}"
	fi

	SYSTEM_JSON="{ \"os\": \"${SYSTEM_OS}\",  \"kernel\": \"${SYSTEM_KERNEL}\" }"
	TIME_JSON="{ \"start\": ${TIME_START}, \"end\": ${TIME_END} }"
	CLI_JSON="{ \"name\": \"${CLI_NAME}\", \"path\": \"${CLI_PATH}\", \"version\": \"${CLI_VERSION}\" }"
	BASELINE_JSON="{ \"name\": \"${BASELINE_CLI_NAME}\", \"path\": \"${BASELINE_CLI_PATH}\", \"version\": \"${BASELINE_CLI_VERSION}\" }"

	if [ "${BASELINE_CLI}" != "" ]; then
		EXECUTOR_JSON="{ \"baseline\": ${BASELINE_JSON}, \"cli\": ${CLI_JSON} }"
	else
		EXECUTOR_JSON="{ \"cli\": ${CLI_JSON} }"
	fi

	# add our metadata to all the test results
	jq -n "{ \"system\": ${SYSTEM_JSON}, \"time\": ${TIME_JSON}, \"executor\": ${EXECUTOR_JSON}, \"tests\": [inputs] }" "${OUTPUT_DIR}"/*.json > "${JSON_RESULT}"
fi

# combine all the data into a zip if requested
if [ "${ZIP_RESULT}" != "" ]; then
	if [ "${VERBOSE}" = "1" ]; then
		if [ "${JSON_RESULT}" = "" ]; then echo ""; fi
		echo "# Writing ZIP results: ${ZIP_RESULT}"
	fi

	zip -jr "${ZIP_RESULT}" "${OUTPUT_DIR}" >/dev/null
fi

if [ "$CLEANUP_DIR" = "1" ]; then
	rm -f "${OUTPUT_DIR}"/*.out
	rm -f "${OUTPUT_DIR}"/*.err
	rm -f "${OUTPUT_DIR}"/*.json
	rmdir "${OUTPUT_DIR}"
fi

if [ "$ANY_FAILED" = "1" ]; then
	exit 1
fi
