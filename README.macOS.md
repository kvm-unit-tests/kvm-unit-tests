# kvm-unit-tests on macOS

The tests can be used to validate TCG or HVF accel on macOS.

## Prerequisites

GNU getopt and coreutils should be installed prior to building and running the
tests. They're available in [homebrew](https://brew.sh):
```
$ brew install coreutils
$ brew install gnu-getopt
```

A cross-compiler with ELF support is required to build kvm-unit-tests on macOS.

### Pre-built cross-compiler

Binary packages of ELF cross-compilers for i386 and x86_64 target can be
installed from homebrew:
```
$ brew install i686-elf-gcc
$ brew install x86_64-elf-gcc
```

Make enhanced getopt available in the current shell session:
```
export PATH="/usr/local/opt/gnu-getopt/bin:$PATH"
```

Then, 32-bit x86 tests can be built like that:
```
$ ./configure \
  --arch=i386 \
  --cross-prefix=i686-elf-
$ make -j $(nproc)
```

64-bit x86 tests can be built likewise:
```
$ ./configure \
  --arch=x86_64 \
  --cross-prefix=x86_64-elf-
$ make -j $(nproc)
```

Out-of-tree build can be used to make tests for both architectures
simultaneously in separate build directories.

### Building cross-compiler from source

An alternative is to build cross-compiler toolchain from source using
crosstool-ng. The latest released version of
[crosstool-ng](https://github.com/crosstool-ng/crosstool-ng) can be installed
using homebrew:
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
$ ./configure \
  --arch=x86_64 \
  --cross-prefix=$X_INSTALL_DIR/x86_64-unknown-linux-gnu/bin/x86_64-unknown-linux-gnu-
$ make -j $(nproc)
```
