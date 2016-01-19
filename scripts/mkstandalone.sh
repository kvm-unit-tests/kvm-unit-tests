#!/bin/bash

if [ ! -f config.mak ]; then
	echo "run ./configure && make first. See ./configure -h"
	exit
fi
source config.mak
source scripts/functions.bash

escape ()
{
	for arg in "${@}"; do
		printf "%q " "$arg"; # XXX: trailing whitespace
	done
}

temp_file ()
{
	local var="$1"
	local file="$2"

	echo "$var=\`mktemp\`"
	echo "cleanup=\"\$$var \$cleanup\""
	echo "base64 -d << 'BIN_EOF' | zcat > \$$var || exit 1"

	gzip - < $file | base64

	echo "BIN_EOF"
	echo "chmod +x \$$var"
}

generate_test ()
{
	local args=( $(escape "${@}") )

	echo "#!/bin/bash"
	grep '^ARCH=' config.mak

	if [ ! -f $kernel ]; then
		echo 'echo "skip '"$testname"' (test kernel not present)"'
		echo 'exit 1'
		return 1
	fi

	echo "trap 'rm -f \$cleanup' EXIT"

	temp_file bin "$kernel"
	args[3]='$bin'

	temp_file RUNTIME_arch_run "$TEST_DIR/run"

	cat scripts/runtime.bash

	echo "run ${args[@]}"
	echo "exit 0"
}

function mkstandalone()
{
	local testname="$1"

	if [ -z "$testname" ]; then
		return 1
	fi

	if [ -n "$one_testname" ] && [ "$testname" != "$one_testname" ]; then
		return 1
	fi

	standalone=tests/$testname

	generate_test "$@" > $standalone

	chmod +x $standalone

	return 0
}

trap 'rm -f $cfg' EXIT
cfg=$(mktemp)

unittests=$TEST_DIR/unittests.cfg
one_kernel="$1"

if [ "$one_kernel" ]; then
	[ ! -f $one_kernel ] && {
		echo "$one_kernel doesn't exist"
		exit 1
	}

	one_kernel_base=$(basename $one_kernel)
	one_testname="${2:-${one_kernel_base%.*}}"

	if grep -q "\[$one_testname\]" $unittests; then
		sed -n "/\\[$one_testname\\]/,/^\\[/p" $unittests \
			| awk '!/^\[/ || NR == 1' > $cfg
	else
		echo "[$one_testname]" > $cfg
		echo "file = $one_kernel_base" >> $cfg
	fi
else
	cp -f $unittests $cfg
fi

mkdir -p tests

for_each_unittest $cfg mkstandalone
