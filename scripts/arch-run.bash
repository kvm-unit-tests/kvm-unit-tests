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

	initrd_create || return $?
	echo -n "$@"
	[ "$ENVIRON_DEFAULT" = "yes" ] && echo -n " #"
	echo " $INITRD"

	# stdout to {stdout}, stderr to $errors and stderr
	exec {stdout}>&1
	errors=$("${@}" $INITRD </dev/null 2> >(tee /dev/stderr) > /dev/fd/$stdout)
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

run_qemu_status ()
{
	local stdout ret

	exec {stdout}>&1
	lines=$(run_qemu "$@" > >(tee /dev/fd/$stdout))
	ret=$?
	exec {stdout}>&-

	if [ $ret -eq 1 ]; then
		testret=$(grep '^EXIT: ' <<<"$lines" | sed 's/.*STATUS=\([0-9][0-9]*\).*/\1/')
		if [ "$testret" ]; then
			if [ $testret -eq 1 ]; then
				ret=0
			else
				ret=$testret
			fi
		fi
	fi

	return $ret
}

timeout_cmd ()
{
	local s

	if [ "$TIMEOUT" ] && [ "$TIMEOUT" != "0" ]; then
		if [ "$CONFIG_EFI" = 'y' ]; then
			s=${TIMEOUT: -1}
			if [ "$s" = 's' ]; then
				TIMEOUT=${TIMEOUT:0:-1}
				((TIMEOUT += 10)) # Add 10 seconds for booting UEFI
				TIMEOUT="${TIMEOUT}s"
			fi
		fi
		echo "timeout -k 1s --foreground $TIMEOUT"
	fi
}

qmp ()
{
	echo '{ "execute": "qmp_capabilities" }{ "execute":' "$2" '}' | ncat -U $1
}

qmp_events ()
{
	while ! test -S "$1"; do sleep 0.1; done
	echo '{ "execute": "qmp_capabilities" }{ "execute": "cont" }' |
		ncat --no-shutdown -U $1 |
		jq -c 'select(has("event"))'
}

run_migration ()
{
	if ! command -v ncat >/dev/null 2>&1; then
		echo "${FUNCNAME[0]} needs ncat (netcat)" >&2
		return 77
	fi

	migsock=$(mktemp -u -t mig-helper-socket.XXXXXXXXXX)
	migout1=$(mktemp -t mig-helper-stdout1.XXXXXXXXXX)
	qmp1=$(mktemp -u -t mig-helper-qmp1.XXXXXXXXXX)
	qmp2=$(mktemp -u -t mig-helper-qmp2.XXXXXXXXXX)
	fifo=$(mktemp -u -t mig-helper-fifo.XXXXXXXXXX)
	qmpout1=/dev/null
	qmpout2=/dev/null

	trap 'kill 0; exit 2' INT TERM
	trap 'rm -f ${migout1} ${migsock} ${qmp1} ${qmp2} ${fifo}' RETURN EXIT

	eval "$@" -chardev socket,id=mon1,path=${qmp1},server=on,wait=off \
		-mon chardev=mon1,mode=control | tee ${migout1} &
	live_pid=`jobs -l %+ | grep "eval" | awk '{print$2}'`

	# We have to use cat to open the named FIFO, because named FIFO's, unlike
	# pipes, will block on open() until the other end is also opened, and that
	# totally breaks QEMU...
	mkfifo ${fifo}
	eval "$@" -chardev socket,id=mon2,path=${qmp2},server=on,wait=off \
		-mon chardev=mon2,mode=control -incoming unix:${migsock} < <(cat ${fifo}) &
	incoming_pid=`jobs -l %+ | awk '{print$2}'`

	# The test must prompt the user to migrate, so wait for the "migrate" keyword
	while ! grep -q -i "Now migrate the VM" < ${migout1} ; do
		if ! ps -p ${live_pid} > /dev/null ; then
			echo "ERROR: Test exit before migration point." >&2
			echo > ${fifo}
			qmp ${qmp1} '"quit"'> ${qmpout1} 2>/dev/null
			qmp ${qmp2} '"quit"'> ${qmpout2} 2>/dev/null
			return 3
		fi
		sleep 1
	done

	qmp ${qmp1} '"migrate", "arguments": { "uri": "unix:'${migsock}'" }' > ${qmpout1}

	# Wait for the migration to complete
	migstatus=`qmp ${qmp1} '"query-migrate"' | grep return`
	while ! grep -q '"completed"' <<<"$migstatus" ; do
		sleep 1
		if ! migstatus=`qmp ${qmp1} '"query-migrate"'`; then
			echo "ERROR: Querying migration state failed." >&2
			echo > ${fifo}
			qmp ${qmp2} '"quit"'> ${qmpout2} 2>/dev/null
			return 2
		fi
		migstatus=`grep return <<<"$migstatus"`
		if grep -q '"failed"' <<<"$migstatus"; then
			echo "ERROR: Migration failed." >&2
			echo > ${fifo}
			qmp ${qmp1} '"quit"'> ${qmpout1} 2>/dev/null
			qmp ${qmp2} '"quit"'> ${qmpout2} 2>/dev/null
			return 2
		fi
	done
	qmp ${qmp1} '"quit"'> ${qmpout1} 2>/dev/null
	echo > ${fifo}
	wait $incoming_pid
	ret=$?

	while (( $(jobs -r | wc -l) > 0 )); do
		sleep 0.5
	done

	return $ret
}

run_panic ()
{
	if ! command -v ncat >/dev/null 2>&1; then
		echo "${FUNCNAME[0]} needs ncat (netcat)" >&2
		return 77
	fi

	if ! command -v jq >/dev/null 2>&1; then
		echo "${FUNCNAME[0]} needs jq" >&2
		return 77
	fi

	qmp=$(mktemp -u -t panic-qmp.XXXXXXXXXX)

	trap 'kill 0; exit 2' INT TERM
	trap 'rm -f ${qmp}' RETURN EXIT

	# start VM stopped so we don't miss any events
	eval "$@" -chardev socket,id=mon1,path=${qmp},server=on,wait=off \
		-mon chardev=mon1,mode=control -S &

	panic_event_count=$(qmp_events ${qmp} | jq -c 'select(.event == "GUEST_PANICKED")' | wc -l)
	if [ "$panic_event_count" -lt 1 ]; then
		echo "FAIL: guest did not panic"
		ret=3
	else
		# some QEMU versions report multiple panic events
		echo "PASS: guest panicked"
		ret=1
	fi

	return $ret
}

migration_cmd ()
{
	if [ "$MIGRATION" = "yes" ]; then
		echo "run_migration"
	fi
}

panic_cmd ()
{
	if [ "$PANIC" = "yes" ]; then
		echo "run_panic"
	fi
}

search_qemu_binary ()
{
	local save_path=$PATH
	local qemucmd qemu

	: "${QEMU_ARCH:=$ARCH_NAME}"

	export PATH=$PATH:/usr/libexec
	for qemucmd in ${QEMU:-qemu-system-$QEMU_ARCH qemu-kvm}; do
		if $qemucmd --help 2>/dev/null | grep -q 'QEMU'; then
			qemu="$qemucmd"
			break
		fi
	done

	if [ -z "$qemu" ]; then
		echo "A QEMU binary was not found." >&2
		echo "You can set a custom location by using the QEMU=<path> environment variable." >&2
		return 2
	fi
	command -v $qemu
	export PATH=$save_path
}

initrd_create ()
{
	if [ "$ENVIRON_DEFAULT" = "yes" ]; then
		trap_exit_push 'rm -f $KVM_UNIT_TESTS_ENV; [ "$KVM_UNIT_TESTS_ENV_OLD" ] && export KVM_UNIT_TESTS_ENV="$KVM_UNIT_TESTS_ENV_OLD" || unset KVM_UNIT_TESTS_ENV; unset KVM_UNIT_TESTS_ENV_OLD'
		[ -f "$KVM_UNIT_TESTS_ENV" ] && export KVM_UNIT_TESTS_ENV_OLD="$KVM_UNIT_TESTS_ENV"
		export KVM_UNIT_TESTS_ENV=$(mktemp)
		env_params
		env_file
		env_errata || return $?
	fi

	unset INITRD
	[ -f "$KVM_UNIT_TESTS_ENV" ] && INITRD="-initrd $KVM_UNIT_TESTS_ENV"

	return 0
}

env_add_params ()
{
	local p

	for p in "$@"; do
		if eval test -v $p; then
			eval export "$p"
		else
			eval export "$p="
		fi
		grep "^$p=" <(env) >>$KVM_UNIT_TESTS_ENV
	done
}

env_params ()
{
	local qemu have_qemu
	local _ rest

	qemu=$(search_qemu_binary) && have_qemu=1

	if [ "$have_qemu" ]; then
		if [ -n "$ACCEL" ] || [ -n "$QEMU_ACCEL" ]; then
			[ -n "$ACCEL" ] && QEMU_ACCEL=$ACCEL
		fi
		QEMU_VERSION_STRING="$($qemu -h | head -1)"
		IFS='[ .]' read -r _ _ _ QEMU_MAJOR QEMU_MINOR QEMU_MICRO rest <<<"$QEMU_VERSION_STRING"
	fi
	env_add_params QEMU_ACCEL QEMU_VERSION_STRING QEMU_MAJOR QEMU_MINOR QEMU_MICRO

	KERNEL_VERSION_STRING=$(uname -r)
	IFS=. read -r KERNEL_VERSION KERNEL_PATCHLEVEL rest <<<"$KERNEL_VERSION_STRING"
	IFS=- read -r KERNEL_SUBLEVEL KERNEL_EXTRAVERSION <<<"$rest"
	KERNEL_SUBLEVEL=${KERNEL_SUBLEVEL%%[!0-9]*}
	KERNEL_EXTRAVERSION=${KERNEL_EXTRAVERSION%%[!0-9]*}
	! [[ $KERNEL_SUBLEVEL =~ ^[0-9]+$ ]] && unset $KERNEL_SUBLEVEL
	! [[ $KERNEL_EXTRAVERSION =~ ^[0-9]+$ ]] && unset $KERNEL_EXTRAVERSION
	env_add_params KERNEL_VERSION_STRING KERNEL_VERSION KERNEL_PATCHLEVEL KERNEL_SUBLEVEL KERNEL_EXTRAVERSION
}

env_file ()
{
	local line var

	[ ! -f "$KVM_UNIT_TESTS_ENV_OLD" ] && return

	for line in $(grep -E '^[[:blank:]]*[[:alpha:]_][[:alnum:]_]*=' "$KVM_UNIT_TESTS_ENV_OLD"); do
		var=${line%%=*}
		if ! grep -q "^$var=" $KVM_UNIT_TESTS_ENV; then
			eval export "$line"
			grep "^$var=" <(env) >>$KVM_UNIT_TESTS_ENV
		fi
	done
}

env_errata ()
{
	if [ "$ACCEL" = "tcg" ]; then
		export "ERRATA_FORCE=y"
	elif [ "$ERRATATXT" ] && [ ! -f "$ERRATATXT" ]; then
		echo "$ERRATATXT not found. (ERRATATXT=$ERRATATXT)" >&2
		return 2
	elif [ "$ERRATATXT" ]; then
		env_generate_errata
	fi
	sort <(env | grep '^ERRATA_') <(grep '^ERRATA_' $KVM_UNIT_TESTS_ENV) | uniq -u >>$KVM_UNIT_TESTS_ENV
}

env_generate_errata ()
{
	local line commit minver errata rest v p s x have

	for line in $(grep -v '^#' "$ERRATATXT" | tr -d '[:blank:]' | cut -d: -f1,2); do
		commit=${line%:*}
		minver=${line#*:}

		test -z "$commit" && continue
		errata="ERRATA_$commit"
		[ -n "${!errata}" ] && continue

		IFS=. read -r v p rest <<<"$minver"
		IFS=- read -r s x <<<"$rest"
		s=${s%%[!0-9]*}
		x=${x%%[!0-9]*}

		if ! [[ $v =~ ^[0-9]+$ ]] || ! [[ $p =~ ^[0-9]+$ ]]; then
			echo "Bad minimum kernel version in $ERRATATXT, $minver"
			return 2
		fi
		! [[ $s =~ ^[0-9]+$ ]] && unset $s
		! [[ $x =~ ^[0-9]+$ ]] && unset $x

		if (( $KERNEL_VERSION > $v ||
		      ($KERNEL_VERSION == $v && $KERNEL_PATCHLEVEL > $p) )); then
			have=y
		elif (( $KERNEL_VERSION == $v && $KERNEL_PATCHLEVEL == $p )); then
			if [ "$KERNEL_SUBLEVEL" ] && [ "$s" ]; then
				if (( $KERNEL_SUBLEVEL > $s )); then
					have=y
				elif (( $KERNEL_SUBLEVEL == $s )); then
					if [ "$KERNEL_EXTRAVERSION" ] && [ "$x" ]; then
						if (( $KERNEL_EXTRAVERSION >= $x )); then
							have=y
						else
							have=n
						fi
					elif [ "$x" ] && (( $x != 0 )); then
						have=n
					else
						have=y
					fi
				else
					have=n
				fi
			elif [ "$s" ] && (( $s != 0 )); then
				have=n
			else
				have=y
			fi
		else
			have=n
		fi
		eval export "$errata=$have"
	done
}

trap_exit_push ()
{
	local old_exit=$(trap -p EXIT | sed "s/^[^']*'//;s/'[^']*$//")
	trap -- "$1; $old_exit" EXIT
}

kvm_available ()
{
	[ -c /dev/kvm ] ||
		return 1

	[ "$HOST" = "$ARCH_NAME" ] ||
		( [ "$HOST" = aarch64 ] && [ "$ARCH" = arm ] ) ||
		( [ "$HOST" = x86_64 ] && [ "$ARCH" = i386 ] )
}

hvf_available ()
{
	[ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ] || return 1
	[ "$HOST" = "$ARCH_NAME" ] ||
		( [ "$HOST" = x86_64 ] && [ "$ARCH" = i386 ] )
}

set_qemu_accelerator ()
{
	ACCEL_PROPS=${ACCEL#"${ACCEL%%,*}"}
	ACCEL=${ACCEL%%,*}

	if [ "$ACCEL" = "kvm" ] && ! kvm_available; then
		echo "KVM is needed, but not available on this host" >&2
		return 2
	fi
	if [ "$ACCEL" = "hvf" ] && ! hvf_available; then
		echo "HVF is needed, but not available on this host" >&2
		return 2
	fi

	if [ -z "$ACCEL" ]; then
		if kvm_available; then
			ACCEL="kvm"
		elif hvf_available; then
			ACCEL="hvf"
		else
			ACCEL="tcg"
		fi
	fi

	return 0
}
