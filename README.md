# Welcome to kvm-unit-tests

See http://www.linux-kvm.org/page/KVM-unit-tests for a high-level
description of this project, as well as running tests and adding
tests HOWTOs.

# Building the tests

This directory contains sources for a kvm test suite.

To create the test images do:

    ./configure
    make

in this directory. Test images are created in ./<ARCH>/*.flat

## Standalone tests

The tests can be built as standalone
To create and use standalone tests do:

    ./configure
    make standalone
    (send tests/some-test somewhere)
    (go to somewhere)
    ./some-test

'make install' will install all tests in PREFIX/share/kvm-unit-tests/tests,
each as a standalone test.


# Running the tests

Then use the runner script to detect the correct invocation and
invoke the test:

    ./x86-run ./x86/msr.flat
or:

    ./run_tests.sh

to run them all.

To select a specific qemu binary, specify the QEMU=<path>
environment variable:

    QEMU=/tmp/qemu/x86_64-softmmu/qemu-system-x86_64 ./x86-run ./x86/msr.flat

# Unit test inputs

Unit tests use QEMU's '-append <args...>' parameter for command line
inputs, i.e. all args will be available as argv strings in main().
Additionally a file of the form

KEY=VAL
KEY2=VAL
...

may be passed with '-initrd <file>' to become the unit test's environ,
which can then be accessed in the usual ways, e.g. VAL = getenv("KEY")
Any key=val strings can be passed, but some have reserved meanings in
the framework. The list of reserved environment variables is below

 QEMU_ACCEL            ... either kvm or tcg
 QEMU_VERSION_STRING   ... string of the form `qemu -h | head -1`
 KERNEL_VERSION_STRING ... string of the form `uname -r`

Additionally these self-explanatory variables are reserved

 QEMU_MAJOR, QEMU_MINOR, QEMU_MICRO, KERNEL_VERSION, KERNEL_PATCHLEVEL,
 KERNEL_SUBLEVEL, KERNEL_EXTRAVERSION

# Guarding unsafe tests

Some tests are not safe to run by default, as they may crash the
host. kvm-unit-tests provides two ways to handle tests like those.

 1) Adding 'nodefault' to the groups field for the unit test in the
    unittests.cfg file. When a unit test is in the nodefault group
    it is only run when invoked

    a) independently, arch-run arch/test
    b) by specifying any other non-nodefault group it is in,
       groups = nodefault,mygroup : ./run_tests.sh -g mygroup
    c) by specifying all tests should be run, ./run_tests.sh -a

 2) Making the test conditional on errata in the code,
    if (ERRATA(abcdef012345)) {
        do_unsafe_test();
    }

    With the errata condition the unsafe unit test is only run
    when

    a) the ERRATA_abcdef012345 environ variable is provided and 'y'
    b) the ERRATA_FORCE environ variable is provided and 'y'
    c) by specifying all tests should be run, ./run_tests.sh -a
       (The -a switch ensures the ERRATA_FORCE is provided and set
        to 'y'.)

The errata.txt file provides a mapping of the commits needed by errata
conditionals to their respective minimum kernel versions. By default,
when the user does not provide an environ, then an environ generated
from the errata.txt file and the host's kernel version is provided to
all unit tests.

# Contributing

## Directory structure

    .:				configure script, top-level Makefile, and run_tests.sh
    ./scripts:		helper scripts for building and running tests
    ./lib:			general architecture neutral services for the tests
    ./lib/<ARCH>:	architecture dependent services for the tests
    ./<ARCH>:		the sources of the tests and the created objects/images

See <ARCH>/README for architecture specific documentation.

## Style

Currently there is a mix of indentation styles so any changes to
existing files should be consistent with the existing style. For new
files:

  - C: please use standard linux-with-tabs, see Linux kernel
    doc Documentation/process/coding-style.rst
  - Shell: use TABs for indentation

Exceptions:

  - While the kernel standard requires 80 columns, we allow up to 120.

## Patches

Patches are welcome at the KVM mailing list <kvm@vger.kernel.org>.

Please prefix messages with: [kvm-unit-tests PATCH]

You can add the following to .git/config to do this automatically for you:

    [format]
        subjectprefix = kvm-unit-tests PATCH

Additionally it's helpful to have a common order of file types in patches.
Our chosen order attempts to place the more declarative files before
the code files. We also start with common code and finish with unit test
code. git-diff's orderFile feature allows us to specify the order in a
file. The orderFile we use is `scripts/git.difforder`. Adding the config
with `git config diff.orderFile scripts/git.difforder` enables it.
