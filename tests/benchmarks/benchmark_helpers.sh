# variables that benchmark tests can set
#

set -eo pipefail

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

#
# parse the arguments to the outer script that's including us; these are arguments that
# the `benchmark.sh` passes (or that a user could specify when running an individual test)
#

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
	else
                echo "$(basename "$0"): unknown option: ${a}" 1>&2
		usage 1>&2
		exit 1
	fi
done

if [ "${NEXT}" != "" ]; then
	echo "$(basename "$0"): option requires a value: --${NEXT}" 1>&2
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
	echo "set -e" >> "${SANDBOX_DIR}/prepare.sh"
	echo "" >> "${SANDBOX_DIR}/prepare.sh"

	# our run script starts by chdir'ing to the sandbox
	echo "cd \"${SANDBOX_DIR}\"" >> "${SANDBOX_DIR}/prepare.sh"

	for a in ${SANDBOX[@]}; do
		echo "" >> "${SANDBOX_DIR}/prepare.sh"
		echo "# sandbox: ${a}" >> "${SANDBOX_DIR}/prepare.sh"
		echo "cp -R \"$(resources_dir)/${a}\" \"${SANDBOX_DIR}/\"" >> "${SANDBOX_DIR}/prepare.sh"
	done

	if [ "${REPOSITORY}" != "" ]; then
		echo "" >> "${SANDBOX_DIR}/prepare.sh"
		echo "# sandbox repository: ${REPOSITORY}" >> "${SANDBOX_DIR}/prepare.sh"
		echo "rm -rf \"${SANDBOX_DIR}/${REPOSITORY}\"" >> "${SANDBOX_DIR}/prepare.sh"
		echo "cp -R \"$(resources_dir)/${REPOSITORY}\" \"${SANDBOX_DIR}/\"" >> "${SANDBOX_DIR}/prepare.sh"
		echo "if [ -d \"${SANDBOX_DIR}/${REPOSITORY}/.gitted\" ]; then mv \"${SANDBOX_DIR}/${REPOSITORY}/.gitted\" \"${SANDBOX_DIR}/${REPOSITORY}/.git\"; fi" >> "${SANDBOX_DIR}/prepare.sh"
		echo "" >> "${SANDBOX_DIR}/prepare.sh"
		echo "cd \"${SANDBOX_DIR}/${REPOSITORY}\"" >> "${SANDBOX_DIR}/prepare.sh"
	fi

	if [ "${PREPARE}" != "" ]; then
		echo "" >> "${SANDBOX_DIR}/prepare.sh"
		echo "${PREPARE}" >> "${SANDBOX_DIR}/prepare.sh"
	fi

	if [ "${FLUSH_DISK_CACHE}" != "" ]; then
		echo "" >> "${SANDBOX_DIR}/prepare.sh"
		echo "$(flush_cache)" >> "${SANDBOX_DIR}/prepare.sh"
	fi

	echo "${SANDBOX_DIR}/prepare.sh"
}

create_runscript() {
	script_name="${1}"; shift
	cli_path="${1}"; shift

	if [ "${REPOSITORY}" != "" ]; then
		START_DIR="${SANDBOX_DIR}/${REPOSITORY}"
	else
		START_DIR="${SANDBOX_DIR}"
	fi

	# our run script starts by chdir'ing to the sandbox or repository directory
	echo -n "cd \"${START_DIR}\" && \"${cli_path}\"" >> "${SANDBOX_DIR}/${script_name}.sh"

	for a in "$@"; do
		echo -n " \"${a}\"" >> "${SANDBOX_DIR}/${script_name}.sh"
	done

	echo "" >> "${SANDBOX_DIR}/${script_name}.sh"
	echo "${SANDBOX_DIR}/${script_name}.sh"
}

gitbench_usage() { echo "usage: gitbench command..."; }

#
# this is the function that the outer script calls to actually do the sandboxing and
# invocation of hyperfine.
#
gitbench() {
	NEXT=

	# these directories will be placed into the sandbox directory out of
	# `tests/resources`
	SANDBOX=()

	# flush the disk cache before the test execution; this will be done after
	# any preparation steps
	FLUSH_DISK_CACHE=

	# this test uses the given repository; the repository in `tests/resources`
	# will be copied into place and the command will start in that directory
	REPOSITORY=

	# this test should run the given command in preparation of the tests
	# this preparation script will be run _after_ repository creation and
	# _before_ flushing the disk cache
	PREPARE=

	# this test should run `n` warmups
	WARMUP=0

	if [ "$*" = "" ]; then
		gitbench_usage 1>&2
		exit 1
	fi

	for a in "$@"; do
		if [ "${NEXT}" = "sandbox" ]; then
			SANDBOX+=("${a}")
			NEXT=
		elif [ "${NEXT}" = "warmup" ]; then
			WARMUP="${a}"
			NEXT=
		elif [ "${NEXT}" = "repository" ]; then
			REPOSITORY="${a}"
			NEXT=
		elif [ "${NEXT}" = "prepare" ]; then
			PREPARE="${a}"
			NEXT=
		elif [ "${a}" = "--sandbox" ]; then
			NEXT="sandbox"
		elif [ "${a}" = "--warmup" ]; then
			NEXT="warmup"
		elif [ "${a}" = "--repository" ]; then
			NEXT="repository"
		elif [ "${a}" = "--prepare" ]; then
			NEXT="prepare"
		elif [ "${a}" = "--flush-disk-cache" ]; then
			FLUSH_DISK_CACHE=1
		elif [[ "${a}" == "--"* ]]; then
			echo "unknown argument: \"${a}\"" 1>&2
			gitbench_usage 1>&2
			exit 1
		else
			break
		fi

		shift
	done

	if [ "${NEXT}" != "" ]; then
		echo "$(basename "$0"): option requires a value: --${NEXT}" 1>&2
		gitbench_usage 1>&2
		exit 1
	fi

	# sanity check

	for a in ${SANDBOX[@]}; do
		if [ ! -d "$(resources_dir)/${a}" ]; then
			echo "$0: no resource '${a}' found" 1>&2
			exit 1
		fi
	done

	if [ "$REPOSITORY" != "" ]; then
		if [ ! -d "$(resources_dir)/${REPOSITORY}" ]; then
			echo "$0: no repository resource '${REPOSITORY}' found" 1>&2
			exit 1
		fi
	fi

	# set up our sandboxing

	SANDBOX_DIR="$(temp_dir)"

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

#	hyperfine "${ARGUMENTS[@]}"
	rm -rf "${SANDBOX_DIR}"
}
