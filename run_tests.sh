#!/usr/bin/env bash

verbose="no"
tap_output="no"
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

Usage: $0 [-h] [-v] [-a] [-g group] [-j NUM-TASKS] [-t]

    -h, --help      Output this help text
    -v, --verbose   Enables verbose mode
    -a, --all       Run all tests, including those flagged as 'nodefault'
                    and those guarded by errata.
    -g, --group     Only execute tests in the given group
    -j, --parallel  Execute tests in parallel
    -t, --tap13     Output test results in TAP format

Set the environment variable QEMU=/path/to/qemu-system-ARCH to
specify the appropriate qemu binary for ARCH-run.

EOF
}

RUNTIME_arch_run="./$TEST_DIR/run"
source scripts/runtime.bash

# require enhanced getopt
getopt -T > /dev/null
if [ $? -ne 4 ]; then
    echo "Enhanced getopt is not available, add it to your PATH?"
    exit 1
fi

only_tests=""
args=$(getopt -u -o ag:htj:v -l all,group:,help,tap13,parallel:,verbose -- $*)
[ $? -ne 0 ] && exit 2;
set -- $args;
while [ $# -gt 0 ]; do
    case "$1" in
        -a | --all)
            run_all_tests="yes"
            export ERRATA_FORCE=y
            ;;
        -g | --group)
            shift
            only_group=$1
            ;;
        -h | --help)
            usage
            exit
            ;;
        -j | --parallel)
            shift
            unittest_run_queues=$1
            if (( $unittest_run_queues <= 0 )); then
                echo "Invalid -j option: $unittest_run_queues"
                exit 2
            fi
            ;;
        -v | --verbose)
            verbose="yes"
            ;;
        -t | --tap13)
            tap_output="yes"
            ;;
        --)
            ;;
        *)
            only_tests="$only_tests $1"
            ;;
    esac
    shift
done

# RUNTIME_log_file will be configured later
if [[ $tap_output == "no" ]]; then
    process_test_output() { cat >> $RUNTIME_log_file; }
    postprocess_suite_output() { cat; }
else
    process_test_output() {
        local testname="$1"
        CR=$'\r'
        while read -r line; do
            line="${line%$CR}"
            case "${line:0:4}" in
                PASS)
                    echo "ok TEST_NUMBER - ${testname}: ${line#??????}" >&3
                    ;;
                FAIL)
                    echo "not ok TEST_NUMBER - ${testname}: ${line#??????}" >&3
                    ;;
                SKIP)
                    echo "ok TEST_NUMBER - ${testname}: ${line#??????} # skip" >&3
                    ;;
                *)
                    ;;
            esac
            echo "${line}"
        done >> $RUNTIME_log_file
    }
    postprocess_suite_output() {
        test_number=0
        while read -r line; do
            case "${line}" in
                ok*|"not ok"*)
                    (( test_number++ ))
                    echo "${line/TEST_NUMBER/${test_number}}" ;;
                *) echo "${line}" ;;
            esac
        done
        echo "1..$test_number"
    }
fi

RUNTIME_log_stderr () { process_test_output "$1"; }
RUNTIME_log_stdout () {
    local testname="$1"
    if [ "$PRETTY_PRINT_STACKS" = "yes" ]; then
        local kernel="$2"
        ./scripts/pretty_print_stacks.py "$kernel" | process_test_output "$testname"
    else
        process_test_output "$testname"
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

if [[ $tap_output == "yes" ]]; then
    echo "TAP version 13"
fi

trap "wait; exit 130" SIGINT

(
   # preserve stdout so that process_test_output output can write TAP to it
   exec 3>&1
   test "$tap_output" == "yes" && exec > /dev/null
   for_each_unittest $config run_task
) | postprocess_suite_output

# wait until all tasks finish
wait
