#!/bin/bash

if [ ! -f config.mak ]; then
    echo "run ./configure && make first. See ./configure -h"
    exit
fi
source config.mak
source scripts/functions.bash

config=$TEST_DIR/unittests.cfg
qemu=${QEMU:-qemu-system-$ARCH}
verbose=0

function run()
{
    local testname="$1"
    local groups="$2"
    local smp="$3"
    local kernel="$4"
    local opts="$5"
    local arch="$6"
    local check="$7"
    local accel="$8"

    if [ -z "$testname" ]; then
        return
    fi

    if [ -n "$only_group" ] && ! grep -q "$only_group" <<<$groups; then
        return
    fi

    if [ -n "$arch" ] && [ "$arch" != "$ARCH" ]; then
        echo "skip $1 ($arch only)"
        return
    fi

    # check a file for a particular value before running a test
    # the check line can contain multiple files to check separated by a space
    # but each check parameter needs to be of the form <path>=<value>
    for check_param in ${check[@]}; do
        path=${check_param%%=*}
        value=${check_param#*=}
        if [ "$path" ] && [ "$(cat $path)" != "$value" ]; then
            echo "skip $1 ($path not equal to $value)"
            return
        fi
    done

    cmdline="TESTNAME=$testname ACCEL=$accel ./$TEST_DIR-run $kernel -smp $smp $opts"
    if [ $verbose != 0 ]; then
        echo $cmdline
    fi

    # extra_params in the config file may contain backticks that need to be
    # expanded, so use eval to start qemu
    eval $cmdline >> test.log

    if [ $? -le 1 ]; then
        echo -e "\e[32mPASS\e[0m $1"
    else
        echo -e "\e[31mFAIL\e[0m $1"
    fi
}

function usage()
{
cat <<EOF

Usage: $0 [-g group] [-h] [-v]

    -g: Only execute tests in the given group
    -h: Output this help text
    -v: Enables verbose mode

Set the environment variable QEMU=/path/to/qemu-system-ARCH to
specify the appropriate qemu binary for ARCH-run.

EOF
}

echo > test.log
while getopts "g:hv" opt; do
    case $opt in
        g)
            only_group=$OPTARG
            ;;
        h)
            usage
            exit
            ;;
        v)
            verbose=1
            ;;
        *)
            exit
            ;;
    esac
done

#
# Probe for MAX_SMP
#
MAX_SMP=$(getconf _NPROCESSORS_CONF)
while ./$TEST_DIR-run _NO_FILE_4Uhere_ -smp $MAX_SMP \
		|& grep -q 'exceeds max cpus'; do
	((--MAX_SMP))
done

for_each_unittest $config run
