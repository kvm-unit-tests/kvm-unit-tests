: "${RUNTIME_arch_run?}"

qemu=${QEMU:-qemu-system-$ARCH}

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

    if [ -z "$testname" ]; then
        return
    fi

    if [ -n "$only_group" ] && ! grep -q "$only_group" <<<$groups; then
        return
    fi

    if [ -n "$arch" ] && [ "$arch" != "$ARCH" ]; then
        echo "skip $1 ($arch only)"
        return 2
    fi

    # check a file for a particular value before running a test
    # the check line can contain multiple files to check separated by a space
    # but each check parameter needs to be of the form <path>=<value>
    for check_param in ${check[@]}; do
        path=${check_param%%=*}
        value=${check_param#*=}
        if [ "$path" ] && [ "$(cat $path)" != "$value" ]; then
            echo "skip $1 ($path not equal to $value)"
            return 2
        fi
    done

    cmdline="TESTNAME=$testname ACCEL=$accel $RUNTIME_arch_run $kernel -smp $smp $opts"
    if [ "$verbose" = "yes" ]; then
        echo $cmdline
    fi

    # extra_params in the config file may contain backticks that need to be
    # expanded, so use eval to start qemu
    eval $cmdline
    ret=$?

    if [ $ret -eq 0 ]; then
        echo -e "\e[32mPASS\e[0m $1"
    else
        echo -e "\e[31mFAIL\e[0m $1"
    fi

    return $ret
}

: ${MAX_SMP:=$(getconf _NPROCESSORS_CONF)}
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
