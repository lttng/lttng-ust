lttng_ust_elf unit tests
========================

This is a series of unit tests for LTTng UST's ELF parser. The parser
is used to retrieve memory size, build ID, and debug link information
from ELF objects (standalone executable or shared object) for base
address statedump or dl events.

The parser should technically be able to read ELF files from any 32-
or 64-bit architecture, little- or big- endian.

However, to restrict the total amount of testing done, only 4
architectures representing all combinations of bitness and endianness
are currently tested:

* x86
* x86_64
* armeb
* aarch64_be

For each architecture, there is a corresponding subdirectory under
`data`, and each of these directories contains exactly 2 files,
`main.elf` and `main.elf.debug`.

The ELF files are generated from the trivial `main.c` program found in
`data/`, using GNU toolchains. The program contains a static array in
order to ensure the creation of a `.bss` section in the ELF file,
which is one of the multiple factors leading to different file and
in-memory size.

The program is compiled with `gcc -g main.c -o main.elf`. On certain
architectures, it is necessary to explicitly specify the
`-Wl,--build-id=sha1` flags to include a build ID in the resulting
executable.

The debug information bundled in `main.elf` is then copied into
`main.elf.debug` and stripped, and a debug link pointing to this file
is added to the executable. The commands used are as follow:

    $ objcopy --only-keep-debug main.elf main.elf.debug
    $ strip -g main.elf
    $ objcopy --add-gnu-debuglink=main.elf.debug main.elf

There is also a series of tests used to check detection of
position-independent code (PIC). These tests use three pre-compiled
ELF files found under `data/pic/`, namely `hello.exec`, `hello.pie`,
and `hello.pic`. These can be re-generated using the files `hello.c`
and `libhello.c`, with the following commands:

    $ gcc hello.c -o hello.exec
    $ gcc hello.c -fPIC -pie -o hello.pie
    $ gcc -shared -o hello.pic -fPIC libhello.c
