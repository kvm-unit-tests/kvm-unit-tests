# The following parameters are enabled by default when running a test with
# kvmtool:
# --nodefaults: suppress VM configuration that cannot be disabled (like
#               modifying the supplied kernel command line). Otherwise tests
#               that use the command line will fail without this parameter.
# --network mode=none: do not create a network device. kvmtool tries to help the
#               user by automatically create one, and then prints a warning
#               when the VM terminates if the device hasn't been initialized.
# --loglevel=warning: reduce verbosity
: "${KVMTOOL_DEFAULT_OPTS:="--nodefaults --network mode=none --loglevel=warning"}"

##############################################################################
# qemu_fixup_return_code translates the ambiguous exit status in Table1 to that
# in Table2.  Table3 simply documents the complete status table.
#
# Table1: Before fixup
# --------------------
# 0      - Unexpected exit from QEMU (possible signal), or the unittest did
#          not use debug-exit
# 1      - most likely unittest succeeded, or QEMU failed
#
# Table2: After fixup
# -------------------
# 0      - Everything succeeded
# 1      - most likely QEMU failed
#
# Table3: Complete table
# ----------------------
# 0      - SUCCESS
# 1      - most likely QEMU failed
# 2      - most likely a run script failed
# 3      - most likely the unittest failed
# 124    - most likely the unittest timed out
# 127    - most likely the unittest called abort()
# 1..127 - FAILURE (could be QEMU, a run script, or the unittest)
# >= 128 - Signal (signum = status - 128)
##############################################################################
function qemu_fixup_return_code()
{
	local ret=$1
	# Remove $ret from the list of arguments
	shift 1
	local errors=$*
	local sig

	[ $ret -eq 134 ] && echo "QEMU Aborted" >&2

	if [ "$errors" ]; then
		sig=$(grep 'terminating on signal' <<<"$errors")
		if [ "$sig" ]; then
			# This is too complex for ${var/search/replace}
			# shellcheck disable=SC2001
			sig=$(sed 's/.*terminating on signal \([0-9][0-9]*\).*/\1/' <<<"$sig")
		fi
	fi

	if [ $ret -eq 0 ]; then
		# Some signals result in a zero return status, but the
		# error log tells the truth.
		if [ "$sig" ]; then
			((ret=sig+128))
		else
			# Exiting with zero (non-debugexit) is an error
			ret=1
		fi
	elif [ $ret -eq 1 ]; then
		# Even when ret==1 (unittest success) if we also got stderr
		# logs, then we assume a QEMU failure. Otherwise we translate
		# status of 1 to 0 (SUCCESS)
	        if [ "$errors" ]; then
			if ! grep -qvi warning <<<"$errors" ; then
				ret=0
			fi
		else
			ret=0
		fi
	fi

	echo $ret
}

function qemu_parse_premature_failure()
{
	local log=$*

	echo "$log" | grep "_NO_FILE_4Uhere_" |
		grep -q -e "[Cc]ould not \(load\|open\) kernel" \
			-e "error loading" \
			-e "failed to load" &&
		return 1
	return 0
}

#
# Probe for MAX_SMP, in case it's less than the number of host cpus.
#
function qemu_probe_maxsmp()
{
	local runtime_arch_run="$1"
	local smp

	if smp=$($runtime_arch_run _NO_FILE_4Uhere_ -smp $MAX_SMP |& grep 'SMP CPUs'); then
		smp=${smp##* }
		smp=${smp/\(}
		smp=${smp/\)}
		echo "Restricting MAX_SMP from ($MAX_SMP) to the max supported ($smp)" >&2
		MAX_SMP=$smp
	fi
}

function kvmtool_fixup_return_code()
{
	local ret=$1

	# Force run_test_status() to interpret the STATUS line.
	if [ $ret -eq 0 ]; then
		ret=1
	fi

	echo $ret
}

function kvmtool_parse_premature_failure()
{
	local log=$*

	echo "$log" | grep "Fatal: Unable to open kernel _NO_FILE_4Uhere_" &&
		return 1
	return 0
}

function kvmtool_probe_maxsmp()
{
	echo "kvmtool automatically limits the number of VCPUs to maximum supported"
	echo "The 'smp' test parameter won't be modified"
}

declare -A vmm_optname=(
	[qemu,args]='-append'
	[qemu,default_opts]=''
	[qemu,fixup_return_code]=qemu_fixup_return_code
	[qemu,initrd]='-initrd'
	[qemu,nr_cpus]='-smp'
	[qemu,parse_premature_failure]=qemu_parse_premature_failure
	[qemu,probe_maxsmp]=qemu_probe_maxsmp

	[kvmtool,args]='--params'
	[kvmtool,default_opts]="$KVMTOOL_DEFAULT_OPTS"
	[kvmtool,fixup_return_code]=kvmtool_fixup_return_code
	[kvmtool,initrd]='--initrd'
	[kvmtool,nr_cpus]='--cpus'
	[kvmtool,parse_premature_failure]=kvmtool_parse_premature_failure
	[kvmtool,probe_maxsmp]=kvmtool_probe_maxsmp
)

function vmm_optname_args()
{
	echo ${vmm_optname[$(vmm_get_target),args]}
}

function vmm_default_opts()
{
	echo ${vmm_optname[$(vmm_get_target),default_opts]}
}

function vmm_fixup_return_code()
{
	${vmm_optname[$(vmm_get_target),fixup_return_code]} "$@"
}

function vmm_optname_initrd()
{
	echo ${vmm_optname[$(vmm_get_target),initrd]}
}

function vmm_optname_nr_cpus()
{
	echo ${vmm_optname[$(vmm_get_target),nr_cpus]}
}

function vmm_parse_premature_failure()
{
	${vmm_optname[$(vmm_get_target),parse_premature_failure]} "$@"
}

function vmm_probe_maxsmp()
{
	${vmm_optname[$(vmm_get_target),probe_maxsmp]} "$1"
}

function vmm_get_target()
{
	if [[ -z "$TARGET" ]]; then
		echo "qemu"
	else
		echo "$TARGET"
	fi
}

function vmm_check_supported()
{
	# We're not interested in the return code for vmm_get_target().
	# shellcheck disable=SC2155
	local target=$(vmm_get_target)

	case "$target" in
	qemu | kvmtool)
		return 0
		;;
	*)
		echo "$0 does not support target '$target'"
		exit 2
		;;
	esac
}

function vmm_unittest_params_name()
{
	# shellcheck disable=SC2155
	local target=$(vmm_get_target)

	case "$target" in
	qemu)
		echo "extra_params|qemu_params"
		;;
	kvmtool)
		echo "kvmtool_params"
		;;
	*)
		echo "$0 does not support '$target'"
		exit 2
		;;
	esac
}
