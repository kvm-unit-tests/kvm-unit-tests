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
	local opts=$6
	local arch=$7
	local machine=$8
	local check=$9
	local accel=${10}
	local timeout=${11}

	# run the normal test case
	"$cmd" "$testname" "$groups" "$smp" "$kernel" "$opts" "$arch" "$machine" "$check" "$accel" "$timeout"

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
	"$cmd" "$testname" "$groups pv" "$smp" "$kernel" "$opts" "$arch" "$machine" "$check" "$accel" "$timeout"
}
