# variables that benchmark tests can set
#

set -eo pipefail

# this test should flush the disk cache before runs
FLUSH_DISK_CACHE=

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
                path="$(which "${path}")"
                if [ "$?" != "0" ]; then exit 1; fi
	else
		path="$(echo "$(cd "$(dirname "${path}")" && pwd)/$(basename "${path}")")"
	fi

	if [[ "$(uname -s)" == "MINGW"* ]]; then path="$(cygpath -w "${path}")"; fi
	echo "${path}"
}

resources_dir() {
	cd "$(dirname "$0")/../resources" && pwd
}

temp_dir() {
	if [ "$(uname -s)" == "Darwin" ]; then
		mktemp -dt libgit2_bench
	else
		mktemp -dt libgit2_bench.XXXXXXX
	fi
}

create_preparescript() {
	echo "set -e" >> "${SANDBOX}/prepare.sh"
	echo "" >> "${SANDBOX}/prepare.sh"

	# our run script starts by chdir'ing to the sandbox
	echo "cd \"${SANDBOX}\"" >> "${SANDBOX}/prepare.sh"

	if [ "${REPOSITORY}" != "" ]; then
		echo "" >> "${SANDBOX}/prepare.sh"
		echo "rm -rf \"${SANDBOX}/${REPOSITORY}\"" >> "${SANDBOX}/prepare.sh"
		echo "cp -R \"$(resources_dir)/${REPOSITORY}\" \"${SANDBOX}/\"" >> "${SANDBOX}/prepare.sh"
		echo "if [ -d \"${SANDBOX}/${REPOSITORY}/.gitted\" ]; then mv \"${SANDBOX}/${REPOSITORY}/.gitted\" \"${SANDBOX}/${REPOSITORY}/.git\"; fi" >> "${SANDBOX}/prepare.sh"
		echo "" >> "${SANDBOX}/prepare.sh"
		echo "cd \"${SANDBOX}/${REPOSITORY}\"" >> "${SANDBOX}/prepare.sh"
	fi

	if [ "$PREPARE" != "" ]; then
		echo "" >> "${SANDBOX}/prepare.sh"
		echo "${PREPARE}" >> "${SANDBOX}/prepare.sh"
	fi

	if [ "$FLUSH_DISK_CACHE" != "" ]; then
		echo "" >> "${SANDBOX}/prepare.sh"
		echo "$(flush_cache)" >> "${SANDBOX}/prepare.sh"
	fi

	echo "${SANDBOX}/prepare.sh"
}

create_runscript() {
	script_name="${1}"; shift
	cli_path="${1}"; shift

	# our run script starts by chdir'ing to the sandbox or repository directory
	echo -n "cd \"${START_DIR}\" && \"${cli_path}\"" >> "${SANDBOX}/${script_name}.sh"

	for a in "$@"; do
		echo -n " \"${a}\"" >> "${SANDBOX}/${script_name}.sh"
	done

	echo "" >> "${SANDBOX}/${script_name}.sh"
	echo "${SANDBOX}/${script_name}.sh"
}

gitbench() {
	if [ "$*" = "" ]; then
		echo "usage: gitbench command..." 1>&2
		exit 1
	fi

	echo "sandbox is: ${SANDBOX}" 1>&2

	SANDBOX="${SANDBOX:=$(temp_dir)}"
	START_DIR="${SANDBOX}"

	echo "sandbox is: ${SANDBOX}" 1>&2

	if [ "$REPOSITORY" != "" ]; then
		if [ ! -d "$(resources_dir)/${REPOSITORY}" ]; then
			echo "$0: no repository resource '${REPOSITORY}' found" 1>&2
			exit 1
		fi

		START_DIR="${SANDBOX}/${REPOSITORY}"
	fi

	if [ "${BASELINE_CLI}" != "" ]; then
		BASELINE_CLI_PATH=$(fullpath "${BASELINE_CLI}")
		BASELINE_RUN_SCRIPT=$(create_runscript "baseline" "${BASELINE_CLI_PATH}" "$@")
	fi
	TEST_CLI_PATH=$(fullpath "${TEST_CLI}")
	TEST_RUN_SCRIPT=$(create_runscript "test" "${TEST_CLI_PATH}" "$@")

	PREPARE_SCRIPT="$(create_preparescript)"
	ARGUMENTS=("--prepare" "bash ${PREPARE_SCRIPT}" "--warmup" "${WARMUP}")

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
		ARGUMENTS+=("-n" "${BASELINE_CLI} ${1}" "bash ${BASELINE_RUN_SCRIPT}")
	fi

	ARGUMENTS+=("-n" "${TEST_CLI} ${1}" "bash ${TEST_RUN_SCRIPT}")

	echo hyperfine "${ARGUMENTS[@]}"

	echo "${SANDBOX}"
#	rm -rf "${SANDBOX}"
}
