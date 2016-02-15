#!/bin/bash

verbose="no"

if [ ! -f config.mak ]; then
    echo "run ./configure && make first. See ./configure -h"
    exit
fi
source config.mak
source scripts/functions.bash

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

RUNTIME_arch_run="./$TEST_DIR/run"
source scripts/runtime.bash

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
            verbose="yes"
            ;;
        *)
            exit
            ;;
    esac
done

RUNTIME_arch_run="./$TEST_DIR/run >> test.log"
config=$TEST_DIR/unittests.cfg
rm -f test.log
echo > test.log
for_each_unittest $config run
