# The file scripts/common.bash has to be the only file sourcing this
# arch helper file
source config.mak

ARCH_CMD=arch_cmd_s390x

function arch_cmd_s390x()
{
	local cmd=$1
	local testname=$2
	local groups=$3
	local smp=$4
	local kernel=$5
	local test_args=$6
	local opts=$7
	local arch=$8
	local machine=$9
	local check=${10}
	local accel=${11}
	local timeout=${12}

	# run the normal test case
	"$cmd" "$testname" "$groups" "$smp" "$kernel" "$test_args" "$opts" "$arch" "$machine" "$check" "$accel" "$timeout"

	# run PV test case
	if [ "$accel" = 'tcg' ] || grep -q "migration" <<< "$groups"; then
		return
	fi
	kernel=${kernel%.elf}.pv.bin
	testname=${testname}_PV
	if [ ! -f "${kernel}" ]; then
		if [ -z "${HOST_KEY_DOCUMENT}" ]; then
			return 2
		fi

		print_result 'SKIP' $testname '' 'PVM image was not created'
		return 2
	fi
	"$cmd" "$testname" "$groups pv" "$smp" "$kernel" "$test_args" "$opts" "$arch" "$machine" "$check" "$accel" "$timeout"
}
