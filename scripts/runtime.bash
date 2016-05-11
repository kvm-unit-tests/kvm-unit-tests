: "${RUNTIME_arch_run?}"
: ${MAX_SMP:=$(getconf _NPROCESSORS_CONF)}
: ${TIMEOUT:=90s}

PASS() { echo -ne "\e[32mPASS\e[0m"; }
SKIP() { echo -ne "\e[33mSKIP\e[0m"; }
FAIL() { echo -ne "\e[31mFAIL\e[0m"; }

extract_summary()
{
    tail -1 | grep '^SUMMARY: ' | sed 's/^SUMMARY: /(/;s/$/)/'
}

function run()
{
    local testname="$1"
    local groups="$2"
    local smp="$3"
    local kernel="$4"
    local opts="$5"
    local arch="$6"
    local check="${CHECK:-$7}"
    local accel="${ACCEL:-$8}"
    local timeout="${9:-$TIMEOUT}" # unittests.cfg overrides the default

    if [ -z "$testname" ]; then
        return
    fi

    if [ -n "$only_group" ] && ! grep -q "$only_group" <<<$groups; then
        return
    fi

    if [ -n "$arch" ] && [ "$arch" != "$ARCH" ]; then
        echo "`SKIP` $1 ($arch only)"
        return 2
    fi

    # check a file for a particular value before running a test
    # the check line can contain multiple files to check separated by a space
    # but each check parameter needs to be of the form <path>=<value>
    for check_param in ${check[@]}; do
        path=${check_param%%=*}
        value=${check_param#*=}
        if [ "$path" ] && [ "$(cat $path)" != "$value" ]; then
            echo "`SKIP` $1 ($path not equal to $value)"
            return 2
        fi
    done

    cmdline="TESTNAME=$testname TIMEOUT=$timeout ACCEL=$accel $RUNTIME_arch_run $kernel -smp $smp $opts"
    if [ "$verbose" = "yes" ]; then
        echo $cmdline
    fi

    # extra_params in the config file may contain backticks that need to be
    # expanded, so use eval to start qemu.  Use "> >(foo)" instead of a pipe to
    # preserve the exit status.
    summary=$(eval $cmdline 2> >(RUNTIME_log_stderr) \
                             > >(tee >(RUNTIME_log_stdout $kernel) | extract_summary))
    ret=$?

    if [ $ret -eq 0 ]; then
        echo "`PASS` $1 $summary"
    elif [ $ret -eq 77 ]; then
        echo "`SKIP` $1 $summary"
    elif [ $ret -eq 124 ]; then
        echo "`FAIL` $1 (timeout; duration=$timeout)"
    else
        echo "`FAIL` $1 $summary"
    fi

    return $ret
}

#
# Probe for MAX_SMP, in case it's less than the number of host cpus.
#
# This probing currently only works for ARM, as x86 bails on another
# error first. Also, this probing isn't necessary for any ARM hosts
# running kernels later than v4.3, i.e. those including ef748917b52
# "arm/arm64: KVM: Remove 'config KVM_ARM_MAX_VCPUS'". So, at some
# point when maintaining the while loop gets too tiresome, we can
# just remove it...
while $RUNTIME_arch_run _NO_FILE_4Uhere_ -smp $MAX_SMP \
		|& grep -qi 'exceeds max CPUs'; do
	((--MAX_SMP))
done
