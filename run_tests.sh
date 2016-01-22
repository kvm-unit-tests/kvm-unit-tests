#!/bin/bash

if [ ! -f config.mak ]; then
    echo "run ./configure && make first. See ./configure -h"
    exit
fi
source config.mak
source scripts/functions.bash

RUNTIME_arch_run="./$TEST_DIR/run"
source scripts/runtime.bash

RUNTIME_arch_run="./$TEST_DIR/run >> test.log"
config=$TEST_DIR/unittests.cfg
echo > test.log
for_each_unittest $config run
