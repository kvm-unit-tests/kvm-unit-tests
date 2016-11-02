##############################################################################
# run_qemu translates the ambiguous exit status in Table1 to that in Table2.
# Table3 simply documents the complete status table.
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
run_qemu ()
{
	local stdout errors ret sig

	# stdout to {stdout}, stderr to $errors and stderr
	exec {stdout}>&1
	errors=$("${@}" 2> >(tee /dev/stderr) > /dev/fd/$stdout)
	ret=$?
	exec {stdout}>&-

	if [ "$errors" ]; then
		sig=$(grep 'terminating on signal' <<<"$errors")
		if [ "$sig" ]; then
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
		if [ -z "$(echo "$errors" | grep -vi warning)" ]; then
			ret=0
		fi
	fi

	return $ret
}

timeout_cmd ()
{
	if [ "$TIMEOUT" ] && [ "$TIMEOUT" != "0" ]; then
		echo "timeout -k 1s --foreground $TIMEOUT"
	fi
}
