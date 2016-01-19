#!/bin/bash

if [ ! -f config.mak ]; then
    echo "run ./configure && make first. See ./configure -h"
    exit
fi
source config.mak
source scripts/functions.bash

RUNTIME_arch_run="./$TEST_DIR/run >> test.log"
source scripts/runtime.bash

config=$TEST_DIR/unittests.cfg

for_each_unittest $config run
