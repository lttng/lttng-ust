LTTng-UST
=========

The LTTng User Space Tracing (LTTng-UST) library allows any C/C++
application to be instrumented for and traced by
[LTTng](http://lttng.org/). LTTng-UST also includes a logging
back-end for Java applications and various dynamically loadable
user space tracing helpers for any application.


Prerequisites
-------------

LTTng-UST depends on [liburcu](http://liburcu.org/) v0.7.2 at build and
run times. It also optionally depends on libnuma.


Building
--------

### Prerequisites

This source tree is based on the Autotools suite from GNU to simplify
portability. Here are some things you should have on your system in order to
compile the Git repository tree:

  - [GNU Autotools](http://www.gnu.org/software/autoconf/)
    (**Automake >= 1.10**, **Autoconf >= 2.50**,
    **Autoheader >= 2.50**;
    make sure your system-wide `automake` points to a recent version!)
  - **[GNU Libtool](https://www.gnu.org/software/libtool/) >= 2.2**


### Optional dependencies

Optional packages to build LTTng-ust man pages:

  - **[AsciiDoc](http://www.methods.co.nz/asciidoc/) >= 8.4.5**
    (previous versions may work, but were not tested)
  - **[xmlto](https://fedorahosted.org/xmlto/) >= 0.0.21** (previous
    versions may work, but were not tested)

Note that the man pages are already built in a distribution tarball.
In this case, you only need AsciiDoc and xmlto if you indend to modify
the AsciiDoc man page sources.

Needed for `make check` and tests:

  - **[Perl](https://www.perl.org/)**


### Building steps

If you get the tree from the Git repository, you will need to run

    ./bootstrap

in its root. It calls all the GNU tools needed to prepare the tree
configuration.

To build LTTng-UST, do:

    ./configure
    make
    sudo make install
    sudo ldconfig

**Note:** the `configure` script sets `/usr/local` as the default prefix for
files it installs. However, this path is not part of most distributions'
default library path, which will cause builds depending on `liblttng-ust`
to fail unless `-L/usr/local/lib` is added to `LDFLAGS`. You may provide a
custom prefix to `configure` by using the `--prefix` switch
(e.g., `--prefix=/usr`). LTTng-UST needs to be a shared library, _even if_
the tracepoint probe provider is statically linked into the application.


Using
-----

First of all, create an instrumentation header following the
[tracepoint examples](doc/examples).

There are two ways to compile the tracepoint provider and link it with
your application: statically or dynamically. Please follow carefully one
or the other method.


### Static linking

This method links the tracepoint provider with the application,
either directly or through a static library (`.a`):

  1. Into exactly one unit (C/C++ source file) of your _application_,
     define `TRACEPOINT_DEFINE` and include the tracepoint provider
     header.
  2. Include the tracepoint provider header into all C/C++ files using
     the provider and insert tracepoints using the `tracepoint()` macro.
  3. Use `-I.` when compiling the unit defining `TRACEPOINT_DEFINE`
     (e.g., `tp.c`).
  4. Link the application with `-ldl` on Linux, or with `-lc` on BSD,
     and with `-llttng-ust`.

Example:

    gcc -c -I. tp.c
    gcc -c some-source.c
    gcc -c other-source.c
    gcc -o my-app tp.o some-source.o other-source.o -ldl -llttng-ust

Run the application directly:

    ./my-app

Other relevant examples:

  - [`doc/examples/easy-ust`](doc/examples/easy-ust)
  - [`doc/examples/hello-static-lib`](doc/examples/hello-static-lib)


### Dynamic loading

This method decouples the tracepoint provider from the application,
making it dynamically loadable.

  1. Into exactly one unit of your _application_, define
     `TRACEPOINT_DEFINE` _and_ `TRACEPOINT_PROBE_DYNAMIC_LINKAGE`,
     then include the tracepoint provider header.
  2. Include the tracepoint provider header into all C/C++ files using
     the provider and insert tracepoints using the `tracepoint()` macro.
  3. Use `-I.` and `-fpic` when compiling the tracepoint provider
     (e.g., `tp.c`).
  4. Link the tracepoint provider with `-llttng-ust` and make it a
     shared object with `-shared`.
  5. Link the application with `-ldl` on Linux, or with `-lc` on BSD.

Example:

    gcc -c -I. -fpic tp.c
    gcc -o tp.so -shared tp.o -llttng-ust
    gcc -o my-app some-source.c other-source.c -ldl

To run _without_ LTTng-UST support:

    ./my-app

To run with LTTng-UST support (register your tracepoint provider,
`tp.so`):

    LD_PRELOAD=./tp.so ./my-app

You could also use `libdl` directly in your application and `dlopen()`
your tracepoint provider shared object (`tp.so`) to make LTTng-UST
tracing possible.

Other relevant examples:

  - [`doc/examples/demo`](doc/examples/demo)


### Controlling tracing and viewing traces

Use [LTTng-tools](https://lttng.org/download) to control the tracer.
Use [Babeltrace](https://lttng.org/babeltrace) to print traces as a
human-readable text log.


### Environment variables and compile flags

  - `liblttng-ust` debug can be activated by setting the environment
    variable `LTTNG_UST_DEBUG` when launching the user application. It
    can also be enabled at build time by compiling LTTng-UST with
    `-DLTTNG_UST_DEBUG`.
  - The environment variable `LTTNG_UST_REGISTER_TIMEOUT` can be used to
    specify how long the applications should wait for the session
    daemon  _registration done_ command before proceeding to execute the
    main program. The default is 3000 ms (3 seconds). The timeout value
    is specified in milliseconds. The value 0 means _don't wait_. The
    value -1 means _wait forever_. Setting this environment variable to 0
    is recommended for applications with time constraints on the process
    startup time.
  - The compilation flag `-DLTTNG_UST_DEBUG_VALGRIND` should be enabled
    at build time to allow `liblttng-ust` to be used with Valgrind
    (side-effect: disables per-CPU buffering).


### Notes

#### C++ support

Since LTTng-UST 2.3, both tracepoints and tracepoint providers can be
compiled in C++. To compile tracepoint probes in C++, you need
G++ >= 4.7 or Clang.


Contact
-------

Maintainer: [Mathieu Desnoyers](mailto:mathieu.desnoyers@efficios.com)

Mailing list: [`lttng-dev@lists.lttng.org`](https://lttng.org/cgi-bin/mailman/listinfo/lttng-dev)


Package contents
----------------

This package contains the following elements:

  - `doc`: LTTng-UST documentation and examples.
  - `include`: the public header files that will be installed on the
    system.
  - `liblttng-ust`: the actual userspace tracing library that must be
    linked to the instrumented programs.
  - `liblttng-ust-comm`: a static library shared between `liblttng-ust`
    and LTTng-tools, that provides functions that allow these components
    to communicate together.
  - `liblttng-ust-ctl`: a library to control tracing in other processes;
     used by LTTng-tools.
  - `liblttng-ust-cyg-profile`: a library that can be preloaded (using
    `LD_PRELOAD`) to instrument function entries and exits when the target
    application is built with the GCC flag `-finstrument-functions`.
  - `liblttng-ust-dl`: a library that can be preloaded to instrument
    calls to `dlopen()` and `dlclose()`.
  - `liblttng-ust-fork`: a library that is preloaded and that hijacks
    calls to several system calls in order to trace across these calls.
    It _has_ to be preloaded in order to hijack calls. In contrast,
    `liblttng-ust` may be linked at build time.
  - `liblttng-ust-java`: a simple library that uses JNI to allow tracing
    in Java programs. (Configure with `--enable-jni-interface`).
  - `liblttng-ust-java-agent`: a package that includes a JNI library and a
    JAR library to provide an LTTng-UST logging back-end for Java
    applications using Java Util Logging or Log4j. (Configure with
    `--enable-java-agent-jul` or `--enable-java-agent-log4j` or
    `--enable-java-agent-all`).
  - `liblttng-ust-libc-wrapper`: an example library that can be
    preloaded to instrument some calls to libc (currently `malloc()` and
    `free()`) and to POSIX threads (mutexes currently instrumented) in
    any program without need to recompile it.
  - `liblttng-ust-python-agent`: a library used by python-lttngust to allow
    tracing in Python applications. (Configure with `--enable-python-agent`)
  - `libringbuffer`: the ring buffer implementation used within LTTng-UST.
  - `python-lttngust`: a package to provide an LTTng-UST logging back-end
    for Python applications using the standard logging framework.
  - `snprintf`: an asynchronous signal-safe version of `snprintf()`.
  - `tests`: various test programs.
  - `tools`: home of `lttng-gen-tp`.
