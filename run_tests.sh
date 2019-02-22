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

    -h: Output this help text
    -v: Enables verbose mode
    -a: Run all tests, including those flagged as 'nodefault'
        and those guarded by errata.
    -g: Only execute tests in the given group
    -j: Execute tests in parallel
    -t: Output test results in TAP format

Set the environment variable QEMU=/path/to/qemu-system-ARCH to
specify the appropriate qemu binary for ARCH-run.

EOF
}

RUNTIME_arch_run="./$TEST_DIR/run"
source scripts/runtime.bash

while getopts "ag:htj:v" opt; do
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
        t)
            tap_output="yes"
            ;;
        *)
            exit 2
            ;;
    esac
done
shift $((OPTIND - 1))
only_tests="$*"

# RUNTIME_log_file will be configured later
if [[ $tap_output == "no" ]]; then
    process_test_output() { cat >> $RUNTIME_log_file; }
    postprocess_suite_output() { cat; }
else
    process_test_output() {
        CR=$'\r'
        while read -r line; do
            line="${line%$CR}"
            case "${line:0:4}" in
                PASS)
                    echo "ok TEST_NUMBER - ${line#??????}" >&3
                    ;;
                FAIL)
                    echo "not ok TEST_NUMBER - ${line#??????}" >&3
                    ;;
                SKIP)
                    echo "ok TEST_NUMBER - ${line#??????} # skip" >&3
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

RUNTIME_log_stderr () { process_test_output; }
RUNTIME_log_stdout () {
    if [ "$PRETTY_PRINT_STACKS" = "yes" ]; then
        ./scripts/pretty_print_stacks.py $1 | process_test_output
    else
        process_test_output
    fi
}

function run_task()
{
	local testname="$1"
	if [ -z "$testname" ]; then
		return
	fi

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
