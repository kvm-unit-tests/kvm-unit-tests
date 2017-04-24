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
	errors=$("${@}" </dev/null 2> >(tee /dev/stderr) > /dev/fd/$stdout)
	ret=$?
	exec {stdout}>&-

	[ $ret -eq 134 ] && echo "QEMU Aborted" >&2

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

qmp ()
{
	echo '{ "execute": "qmp_capabilities" }{ "execute":' "$2" '}' | nc -U $1
}

run_migration ()
{
	if ! command -v nc >/dev/null 2>&1; then
		echo "$FUNCNAME needs nc (netcat)" >&2
		exit 2
	fi

	qemu=$1
	shift

	migsock=`mktemp -u -t mig-helper-socket.XXXXXXXXXX`
	migout1=`mktemp -t mig-helper-stdout1.XXXXXXXXXX`
	qmp1=`mktemp -u -t mig-helper-qmp1.XXXXXXXXXX`
	qmp2=`mktemp -u -t mig-helper-qmp2.XXXXXXXXXX`
	qmpout1=/dev/null
	qmpout2=/dev/null

	trap 'rm -f ${migout1} ${migsock} ${qmp1} ${qmp2}' EXIT

	$qemu "$@" -chardev socket,id=mon1,path=${qmp1},server,nowait \
		 -mon chardev=mon1,mode=control | tee ${migout1} &

	$qemu "$@" -chardev socket,id=mon2,path=${qmp2},server,nowait \
		 -mon chardev=mon2,mode=control -incoming unix:${migsock} &

	# The test must prompt the user to migrate, so wait for the "migrate" keyword
	while ! grep -q -i "migrate" < ${migout1} ; do
		sleep 1
	done

	qmp ${qmp1} '"migrate", "arguments": { "uri": "unix:'${migsock}'" }' > ${qmpout1}

	# Wait for the migration to complete
	migstatus=`qmp ${qmp1} '"query-migrate"' | grep return`
	while ! grep -q '"completed"' <<<"$migstatus" ; do
		sleep 1
		migstatus=`qmp ${qmp1} '"query-migrate"' | grep return`
		if grep -q '"failed"' <<<"$migstatus" ; then
			echo "ERROR: Migration failed." >&2
			qmp ${qmp1} '"quit"'> ${qmpout1} 2>/dev/null
			qmp ${qmp2} '"quit"'> ${qmpout2} 2>/dev/null
			exit 2
		fi
	done
	qmp ${qmp1} '"quit"'> ${qmpout1} 2>/dev/null

	qmp ${qmp2} '"inject-nmi"'> ${qmpout2}

	wait
}

migration_cmd ()
{
	if [ "$MIGRATION" = "yes" ]; then
		echo "run_migration"
	fi
}

search_qemu_binary ()
{
	local save_path=$PATH
	local qemucmd qemu

	export PATH=$PATH:/usr/libexec
	for qemucmd in ${QEMU:-qemu-system-$ARCH_NAME qemu-kvm}; do
		if $qemucmd --help 2>/dev/null | grep -q 'QEMU'; then
			qemu="$qemucmd"
			break
		fi
	done

	if [ -z "$qemu" ]; then
		echo "A QEMU binary was not found."
		echo "You can set a custom location by using the QEMU=<path> environment variable."
		exit 2
	fi
	command -v $qemu
	export PATH=$save_path
}
