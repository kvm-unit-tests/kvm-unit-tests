declare -A vmm_optname=(
	[qemu,args]='-append'
	[qemu,nr_cpus]='-smp'
)

function vmm_optname_args()
{
	echo ${vmm_optname[$(vmm_get_target),args]}
}

function vmm_optname_nr_cpus()
{
	echo ${vmm_optname[$(vmm_get_target),nr_cpus]}
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
	qemu)
		return 0
		;;
	*)
		echo "$0 does not support target '$target'"
		exit 2
		;;
	esac
}
