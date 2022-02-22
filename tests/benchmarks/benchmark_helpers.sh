# variables that benchmark tests can set
#

set -eo pipefail

# this test should flush the disk cache before runs
FLUSH_DISK_CACHE=0

# this test uses the given repository; the repository in `tests/resources`
# will be copied into place and the command will start in that directory
REPOSITORY=

# this test should run the given command in preparation of the tests
# this preparation script will be run _after_ repository creation and
# _before_ flushing the disk cache
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
	OUTPUT_STYLE="color"
else
	OUTPUT_STYLE="auto"
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
	elif [ "${a}" = "-c" ] || [ "${a}" = "--cli" ]; then
		NEXT="cli"
	elif [[ "${a}" == "-c"* ]]; then
		TEST_CLI="${a/-c/}"
	elif [ "${a}" = "-b" ] || [ "${a}" = "--baseline-cli" ]; then
		NEXT="baseline-cli"
	elif [[ "${a}" == "-b"* ]]; then
		BASELINE_CLI="${a/-b/}"
	elif [ "${a}" == "--output-style" ]; then
		NEXT="output-style"
	elif [ "${a}" = "-j" ] || [ "${a}" = "--json" ]; then
		NEXT="json"
	elif [[ "${a}" == "-j"* ]]; then
		JSON="${a}"
	elif [ "${a}" = "--show-output" ]; then
		SHOW_OUTPUT=1
		OUTPUT_STYLE=
	fi
done

if [ "${NEXT}" != "" ]; then
        usage 1>&2
        exit 1
fi

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
	elif [[ "$(uname -s)" == "MINGW"* ]]; then
		echo "PurgeStandbyList"
	fi
}

fullpath() {
	path="${1}"
	if [[ "$(uname -s)" == "MINGW"* ]]; then path="$(cygpath -u "${1}")"; fi

	if [[ "${path}" != *"/"* ]]; then
		if ! which "${path}"; then
			echo "${1}: command not found" 1>&2
			exit 1
		fi
	else
		echo "$(cd "$(dirname "${path}")" && pwd)/$(basename "${path}")"
	fi

	if [[ "$(uname -s)" == "MINGW"* ]]; then path="$(cygpath -w "${path}")"; fi
	echo "${path}"
}

resources_dir() {
	cd "$(dirname "$0")/../resources" && pwd
}

gitbench() {
	if [ "$1" = "" ]; then
		echo "usage: gitbench command..." 1>&2
		exit 1
	fi

	PREPARE=${PREPARE:="true"}

	SANDBOX="$(mktemp -d)"
	START_DIR="${SANDBOX}"

	if [ "$REPOSITORY" != "" ]; then
		if [ ! -d "$(resources_dir)/${REPOSITORY}" ]; then
			echo "$0: no repository resource '${REPOSITORY}' found" 1>&2
			exit 1
		fi

		START_DIR="${SANDBOX}/${REPOSITORY}"
		PREPARE="rm -rf \"${SANDBOX}/${REPOSITORY}\" &&
			 cp -R \"$(resources_dir)/${REPOSITORY}\" \"${SANDBOX}/\" &&
			 mv \"${SANDBOX}/${REPOSITORY}/.gitted\" \"${SANDBOX}/${REPOSITORY}/.git\" &&
			 (cd \"${START_DIR}\" && ${PREPARE})"
	fi

	if [ "$FLUSH_DISK_CACHE" = "1" ]; then
		PREPARE="${PREPARE} && $(flush_cache)"
	fi

	if [ "${BASELINE_CLI}" != "" ]; then
		BASELINE_CLI_PATH=$(fullpath "${BASELINE_CLI}")
	fi
	TEST_CLI_PATH=$(fullpath "${TEST_CLI}")

	ARGUMENTS=("--prepare" "${PREPARE}" "--warmup" "${WARMUP}")

	if [ "${OUTPUT_STYLE}" != "" ]; then
		ARGUMENTS+=("--style" "${OUTPUT_STYLE}")
	fi

	if [ "${SHOW_OUTPUT}" != "" ]; then
		ARGUMENTS+=("--show-output")
	fi

	if [ "$JSON" != "" ]; then
		ARGUMENTS+=("--export-json" "${JSON}")
	fi

	if [ "${BASELINE_CLI}" != "" ]; then
		ARGUMENTS+=("-n" "${BASELINE_CLI} ${1}" "cd ${START_DIR} && ${BASELINE_CLI_PATH} ${1}")
	fi

	ARGUMENTS+=("-n" "${TEST_CLI} ${1}" "cd ${START_DIR} && ${TEST_CLI_PATH} ${1}")

	hyperfine "${ARGUMENTS[@]}"

	rm -rf "${SANDBOX}"
}
