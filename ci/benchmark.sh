#!/bin/sh

set -e

count=1

indent() { sed "s/^/  /"; }

benchmark() {
	echo ""
	echo "# Benchmark: git $1"
	echo ""

	TMPFILE=$(mktemp)
	hyperfine -s color "git $1" "../build/git2_cli $1" --export-json ${TMPFILE} | indent
	(echo "{ \"name\": \"$1\" }" && cat ${TMPFILE}) | jq -s add > "results/${count}.json"
	rm ${TMPFILE}

	count=$((count+1))
}

echo "##############################################################################"
echo "# Setup"
echo "##############################################################################"

mkdir -p results

echo ""
echo "Creating random data..."
echo ""

dd if=/dev/urandom of="random-1kb" bs=1k count=1 >/dev/null 2>&1
dd if=/dev/urandom of="random-10kb" bs=1k count=10 >/dev/null 2>&1
dd if=/dev/urandom of="random-100kb" bs=1k count=100 >/dev/null 2>&1
dd if=/dev/urandom of="random-1mb" bs=1m count=1 >/dev/null 2>&1
dd if=/dev/urandom of="random-10mb" bs=1m count=10 >/dev/null 2>&1
dd if=/dev/urandom of="random-100mb" bs=1m count=100 >/dev/null 2>&1

echo "##############################################################################"
echo "# Benchmark suite: git hash-object"
echo "##############################################################################"

benchmark "hash-object random-1kb"
benchmark "hash-object random-10kb"
benchmark "hash-object random-100kb"
benchmark "hash-object random-1mb"
benchmark "hash-object random-10mb"
benchmark "hash-object random-100mb"

echo ""
echo "##############################################################################"
echo "# Generating results"
echo "##############################################################################"

cat results/* | jq -s . > results.json

(echo "| Command | git time (ms) | libgit2 time (ms) |" &&
 echo "|---------|---------------|-------------------|" &&
 jq -r '.[] | [ .name, .results[0].mean, .results[0].stddev, .results[1].mean, .results[1].stddev ] | @tsv' < results.json |
	while IFS=$'\t' read -r name git_time git_stddev libgit2_time libgit2_stddev; do
		libgit2_faster=$(echo "${git_time} > ${libgit2_time}" | bc -l)

		if [ "${libgit2_faster}" = "1" ]; then
			libgit2_decoration="✅"
		else
			libgit2_decoration="🛑"
		fi

		printf "| %s | %.2f ± %.2f | %s %.2f ± %.2f |\n" "$name" \
			$(echo "${git_time} * 1000" | bc) \
			$(echo "${git_stddev} * 1000" | bc) \
			"${libgit2_decoration}" \
			$(echo "${libgit2_time} * 1000" | bc) \
			$(echo "${libgit2_stddev} * 1000" | bc)
	done ) > results.md
