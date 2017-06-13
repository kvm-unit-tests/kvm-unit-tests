#!/usr/bin/env bash

verbose="no"
run_all_tests="no" # don't run nodefault tests

if [ ! -f config.mak ]; then
    echo "run ./configure && make first. See ./configure -h"
    exit 1
fi
source config.mak
source scripts/common.bash

function usage()
{
cat <<EOF

Usage: $0 [-h] [-v] [-a] [-g group] [-j NUM-TASKS]

    -h: Output this help text
    -v: Enables verbose mode
    -a: Run all tests, including those flagged as 'nodefault'
        and those guarded by errata.
    -g: Only execute tests in the given group
    -j: Execute tests in parallel

Set the environment variable QEMU=/path/to/qemu-system-ARCH to
specify the appropriate qemu binary for ARCH-run.

EOF
}

RUNTIME_arch_run="./$TEST_DIR/run"
source scripts/runtime.bash

while getopts "ag:hj:v" opt; do
    case $opt in
        a)
            run_all_tests="yes"
            export ERRATA_FORCE=y
            ;;
        g)
            only_group=$OPTARG
            ;;
        h)
            usage
            exit
            ;;
        j)
            unittest_run_queues=$OPTARG
            if (( $unittest_run_queues <= 0 )); then
                echo "Invalid -j option: $unittest_run_queues"
                exit 2
            fi
            ;;
        v)
            verbose="yes"
            ;;
        *)
            exit 2
            ;;
    esac
done

# RUNTIME_log_file will be configured later
RUNTIME_log_stderr () { cat >> $RUNTIME_log_file; }
RUNTIME_log_stdout () {
    if [ "$PRETTY_PRINT_STACKS" = "yes" ]; then
        ./scripts/pretty_print_stacks.py $1 >> $RUNTIME_log_file
    else
        cat >> $RUNTIME_log_file
    fi
}

function run_task()
{
	local testname="$1"

	while (( $(jobs | wc -l) == $unittest_run_queues )); do
		# wait for any background test to finish
		wait -n 2>/dev/null
	done

	RUNTIME_log_file="${unittest_log_dir}/${testname}.log"
	if [ $unittest_run_queues = 1 ]; then
		run "$@"
	else
		run "$@" &
	fi
}

: ${unittest_log_dir:=logs}
: ${unittest_run_queues:=1}
config=$TEST_DIR/unittests.cfg

rm -rf $unittest_log_dir.old
[ -d $unittest_log_dir ] && mv $unittest_log_dir $unittest_log_dir.old
mkdir $unittest_log_dir || exit 2

echo "BUILD_HEAD=$(cat build-head)" > $unittest_log_dir/SUMMARY

trap "wait; exit 130" SIGINT
for_each_unittest $config run_task

# wait until all tasks finish
wait
