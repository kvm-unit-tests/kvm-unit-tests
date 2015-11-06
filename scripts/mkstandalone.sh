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
	cmdline=$(DRYRUN=yes ACCEL=$accel ./$TEST_DIR-run $kernel)
	if [ $? -ne 0 ]; then
		echo $cmdline
		exit 1
	fi
	qemu=$(cut -d' ' -f1 <<< "$cmdline")
	cmdline=$(cut -d' ' -f2- <<< "$cmdline")

	cat <<EOF > $standalone
#!/bin/sh

EOF
if [ "$arch" ]; then
	cat <<EOF >> $standalone
ARCH=\`uname -m | sed -e s/i.86/i386/ | sed -e 's/arm.*/arm/'\`
[ "\$ARCH" = "aarch64" ] && ARCH="arm64"
if [ "\$ARCH" != "$arch" ]; then
	echo "skip $testname ($arch only)" 1>&2
	exit 1
fi

EOF
fi
if [ "$check" ]; then
	cat <<EOF >> $standalone
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
	cat <<EOF >> $standalone
echo "skip $testname (test kernel not present)" 1>&2
exit 1
EOF
else
	cat <<EOF >> $standalone
trap 'rm -f \$bin; exit 1' HUP INT TERM
bin=\`mktemp\`
base64 -d << 'BIN_EOF' | zcat > \$bin &&
EOF
gzip - < $kernel | base64 >> $standalone
	cat <<EOF >> $standalone
BIN_EOF

qemu="$qemu"
if [ "\$QEMU" ]; then
	qemu="\$QEMU"
fi
echo \$qemu $cmdline -smp $smp $opts

cmdline="\`echo '$cmdline' | sed s%$kernel%_NO_FILE_4Uhere_%\`"
if \$qemu \$cmdline 2>&1 | grep 'No accelerator found'; then
        ret=2
else
	cmdline="\`echo '$cmdline' | sed s%$kernel%\$bin%\`"
	\$qemu \$cmdline -smp $smp $opts
	ret=\$?
fi
echo Return value from qemu: \$ret
if [ \$ret -le 1 ]; then
	echo PASS $testname 1>&2
else
	echo FAIL $testname 1>&2
fi
rm -f \$bin
exit 0
EOF
fi
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
