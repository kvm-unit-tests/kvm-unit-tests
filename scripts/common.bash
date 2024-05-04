source config.mak

function for_each_unittest()
{
	local unittests="$1"
	local cmd="$2"
	local testname
	local smp
	local kernel
	local opts
	local groups
	local arch
	local machine
	local check
	local accel
	local timeout
	local rematch

	exec {fd}<"$unittests"

	while read -r -u $fd line; do
		if [[ "$line" =~ ^\[(.*)\]$ ]]; then
			rematch=${BASH_REMATCH[1]}
			if [ -n "${testname}" ]; then
				$(arch_cmd) "$cmd" "$testname" "$groups" "$smp" "$kernel" "$opts" "$arch" "$machine" "$check" "$accel" "$timeout"
			fi
			testname=$rematch
			smp=1
			kernel=""
			opts=""
			groups=""
			arch=""
			machine=""
			check=""
			accel=""
			timeout=""
		elif [[ $line =~ ^file\ *=\ *(.*)$ ]]; then
			kernel=$TEST_DIR/${BASH_REMATCH[1]}
		elif [[ $line =~ ^smp\ *=\ *(.*)$ ]]; then
			smp=${BASH_REMATCH[1]}
		elif [[ $line =~ ^extra_params\ *=\ *'"""'(.*)$ ]]; then
			opts=${BASH_REMATCH[1]}$'\n'
			while read -r -u $fd; do
				#escape backslash newline, but not double backslash
				if [[ $opts =~ [^\\]*(\\*)$'\n'$ ]]; then
					if (( ${#BASH_REMATCH[1]} % 2 == 1 )); then
						opts=${opts%\\$'\n'}
					fi
				fi
				if [[ "$REPLY" =~ ^(.*)'"""'[:blank:]*$ ]]; then
					opts+=${BASH_REMATCH[1]}
					break
				else
					opts+=$REPLY$'\n'
				fi
			done
		elif [[ $line =~ ^extra_params\ *=\ *(.*)$ ]]; then
			opts=${BASH_REMATCH[1]}
		elif [[ $line =~ ^groups\ *=\ *(.*)$ ]]; then
			groups=${BASH_REMATCH[1]}
		elif [[ $line =~ ^arch\ *=\ *(.*)$ ]]; then
			arch=${BASH_REMATCH[1]}
		elif [[ $line =~ ^machine\ *=\ *(.*)$ ]]; then
			machine=${BASH_REMATCH[1]}
		elif [[ $line =~ ^check\ *=\ *(.*)$ ]]; then
			check=${BASH_REMATCH[1]}
		elif [[ $line =~ ^accel\ *=\ *(.*)$ ]]; then
			accel=${BASH_REMATCH[1]}
		elif [[ $line =~ ^timeout\ *=\ *(.*)$ ]]; then
			timeout=${BASH_REMATCH[1]}
		fi
	done
	if [ -n "${testname}" ]; then
		$(arch_cmd) "$cmd" "$testname" "$groups" "$smp" "$kernel" "$opts" "$arch" "$machine" "$check" "$accel" "$timeout"
	fi
	exec {fd}<&-
}

function arch_cmd()
{
	[ "${ARCH_CMD}" ] && echo "${ARCH_CMD}"
}

# The current file has to be the only file sourcing the arch helper
# file. Shellcheck can't follow this so help it out. There doesn't appear to be a
# way to specify multiple alternatives, so we will have to rethink this if things
# get more complicated.
ARCH_FUNC=scripts/${ARCH}/func.bash
if [ -f "${ARCH_FUNC}" ]; then
# shellcheck source=scripts/s390x/func.bash
	source "${ARCH_FUNC}"
fi
