# kvm-unit-tests on macOS

Cross-compiler with ELF support is required for build of kvm-unit-tests on
macOS.

## Building cross-compiler from source

A cross-compiler toolchain can be built from source using crosstool-ng. The
latest released version of
[crosstool-ng](https://github.com/crosstool-ng/crosstool-ng) can be installed
using [homebrew](https://brew.sh)
```
$ brew install crosstool-ng
```

A case-sensitive APFS/HFS+ volume has to be created using Disk Utility as a
build and installation directory for the cross-compiler. Please [see Apple
documentation](https://support.apple.com/guide/disk-utility/dsku19ed921c/mac)
for details.

Assuming the case-sensitive volume is named /Volumes/BuildTools, the
cross-compiler can be built and installed there:
```
$ X_BUILD_DIR=/Volumes/BuildTools/ct-ng-build
$ X_INSTALL_DIR=/Volumes/BuildTools/x-tools
$ mkdir $X_BUILD_DIR
$ ct-ng -C $X_BUILD_DIR x86_64-unknown-linux-gnu
$ ct-ng -C $X_BUILD_DIR build CT_PREFIX=$X_INSTALL_DIR
```

Once compiled, the cross-compiler can be used to build the tests:
```
$ ./configure --cross-prefix=$X_INSTALL_DIR/x86_64-unknown-linux-gnu/bin/x86_64-unknown-linux-gnu-
$ make
```

## Pre-built cross-compiler

x86_64-elf-gcc package in Homebrew provides pre-built cross-compiler but it
fails to compile kvm-unit-tests.

## Running the tests

GNU coreutils should be installed prior to running the tests: 
```
$ brew install coreutils
```
