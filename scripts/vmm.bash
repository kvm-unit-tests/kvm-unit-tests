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
