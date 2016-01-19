#!/bin/bash

if [ ! -f config.mak ]; then
	echo "run ./configure && make first. See ./configure -h"
	exit
fi
source config.mak
source scripts/functions.bash

one_kernel="$1"
[ "$one_kernel" ] && one_kernel_base=$(basename $one_kernel)
one_testname="$2"
if [ -n "$one_kernel" ] && [ ! -f $one_kernel ]; then
	echo "$one_kernel doesn't exist"
	exit 1
elif [ -n "$one_kernel" ] && [ -z "$one_testname" ]; then
	one_testname="${one_kernel_base%.*}"
fi

unittests=$TEST_DIR/unittests.cfg
mkdir -p tests

temp_file ()
{
	local var="$1"
	local file="$2"

	echo "$var=\`mktemp\`"
	echo "cleanup=\"\$$var \$cleanup\""
	echo "base64 -d << 'BIN_EOF' | zcat > \$$var || exit 1"

	gzip - < $file | base64

	echo "BIN_EOF"
	echo "chmod +x \$$var"
}

function mkstandalone()
{
	local testname="$1"
	local groups="$2"
	local smp="$3"
	local kernel="$4"
	local opts="$5"
	local arch="$6"
	local check="$7"
	local accel="$8"

	if [ -z "$testname" ]; then
		return 1
	fi

	if [ -n "$one_testname" ] && [ "$testname" != "$one_testname" ]; then
		return 1
	fi

	standalone=tests/$testname

	exec {tmpfd}<&1
	exec > $standalone

	echo "#!/bin/bash"
	grep '^ARCH=' config.mak

if [ "$check" ]; then
	cat <<EOF
for param in $check; do
	path=\`echo \$param | cut -d= -f1\`
	value=\`echo \$param | cut -d= -f2\`
	if [ -f "\$path" ] && [ "\`cat \$path\`" != "\$value" ]; then
		echo "skip $testname (\$path not equal to \$value)" 1>&2
		exit 1
	fi
done

EOF
fi
	if [ ! -f $kernel ]; then
		echo 'echo "skip '"$testname"' (test kernel not present)" 1>&2'
		echo 'exit 1'
	else
	# XXX: bad indentation

	echo "trap 'rm -f \$cleanup' EXIT"

	temp_file bin "$kernel"
	temp_file RUNTIME_arch_run "$TEST_DIR/run"

	cat <<EOF

MAX_SMP="MAX_SMP"
echo \$RUNTIME_arch_run \$bin -smp $smp $opts

if \$RUNTIME_arch_run _NO_FILE_4Uhere_ 2>&1 | grep 'No accelerator found'; then
	ret=2
else
	MAX_SMP=\`getconf _NPROCESSORS_CONF\`
	while \$RUNTIME_arch_run \$bin -smp \$MAX_SMP 2>&1 | grep 'exceeds max cpus' > /dev/null; do
		MAX_SMP=\`expr \$MAX_SMP - 1\`
	done

	\$RUNTIME_arch_run \$bin -smp $smp $opts
	ret=\$?
fi
if [ \$ret -le 1 ]; then
	echo PASS $testname 1>&2
else
	echo FAIL $testname 1>&2
fi
exit 0
EOF
	fi

	exec 1<&$tmpfd {tmpfd}<&-
	chmod +x $standalone

	return 0
}

trap 'rm -f $cfg; exit 1' HUP INT TERM
trap 'rm -f $cfg' EXIT
cfg=$(mktemp)

if [ -n "$one_testname" ]; then
	if grep -q "\[$one_testname\]" $unittests; then
		sed -n "/\\[$one_testname\\]/,/^\\[/p" $unittests \
			| awk '!/^\[/ || NR == 1' > $cfg
	else
		echo "[$one_testname]" > $cfg
		echo "file = $one_kernel_base" >> $cfg
	fi
else
	cp -f $unittests $cfg
fi

for_each_unittest $cfg mkstandalone
