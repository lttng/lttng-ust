dnl SPDX-License-Identifier: LGPL-2.1-only
dnl
dnl Copyright (C) 2021 EfficiOS, Inc.
dnl
dnl Process this file with autoconf to produce a configure script.


# Project version information
m4_define([ust_version_major], [2])
m4_define([ust_version_minor], [15])
m4_define([ust_version_patch], [0])
m4_define([ust_version_dev_stage], [-pre])
m4_define([ust_version], ust_version_major[.]ust_version_minor[.]ust_version_patch[]ust_version_dev_stage)
m4_define([ust_version_name], [[P-Beer]])
m4_define([ust_version_description], [[An alcoholic drink made from yeast-fermented malt flavored with hops.]])

# Library version information of "liblttng-ust"
# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
m4_define([ust_lib_version_current], [1])
m4_define([ust_lib_version_revision], [0])
m4_define([ust_lib_version_age], [0])
m4_define([ust_lib_version], ust_lib_version_current[:]ust_lib_version_revision[:]ust_lib_version_age)

# Library version information of "liblttng-ust-ctl"
# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
m4_define([ust_ctl_lib_version_current], [6])
m4_define([ust_ctl_lib_version_revision], [0])
m4_define([ust_ctl_lib_version_age], [0])
m4_define([ust_ctl_lib_version], ust_ctl_lib_version_current[:]ust_ctl_lib_version_revision[:]ust_ctl_lib_version_age)


##                     ##
## Autoconf base setup ##
##                     ##

AC_PREREQ([2.69])
AC_INIT([lttng-ust],[ust_version],[mathieu dot desnoyers at efficios dot com],[],[https://lttng.org])

AC_CONFIG_HEADERS([src/common/config.h include/lttng/ust-config.h include/lttng/ust-version.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST


##                     ##
## Automake base setup ##
##                     ##

AM_INIT_AUTOMAKE([1.12 foreign dist-bzip2 no-dist-gzip tar-ustar nostdinc -Wall -Wno-portability -Werror])
AM_MAINTAINER_MODE([enable])

# Enable silent rules by default
AM_SILENT_RULES([yes])


##                               ##
## OS and Arch specific defaults ##
##                               ##

# Set os specific options
AS_CASE([$host_os],
  [freebsd*], [AE_FEATURE_DISABLE([numa])]
)

# Set architecture specific options
AS_CASE([$host_cpu],
  [i[[3456]]86], [],
  [x86_64], [],
  [amd64], [],
  [powerpc], [],
  [ppc64], [],
  [ppc64le], [],
  [powerpc64], [],
  [powerpc64le], [],
  [s390], [],
  [s390x], [],
  [arm*], [AE_FEATURE_DISABLE([numa])],
  [aarch64*], [],
  [mips*], [],
  [tile*], [],
  [
    unsupported_arch="yes"
  ])


##                   ##
## C compiler checks ##
##                   ##

# Choose the C compiler
AC_PROG_CC
# AC_PROG_CC_STDC was merged in AC_PROG_CC in autoconf 2.70
m4_version_prereq([2.70], [], [AC_PROG_CC_STDC])

# Make sure the C compiler supports C99
AS_IF([test "$ac_cv_prog_cc_c99" = "no"], [AC_MSG_ERROR([The compiler does not support C99])])

# Enable available system extensions and LFS support
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

# Make sure the C compiler supports __attribute__
AX_C___ATTRIBUTE__
AS_IF([test "x$ax_cv___attribute__" != "xyes"],
  [AC_MSG_ERROR([The compiler does not support __attribute__ extensions])])

# Make sure we have pthread support
AX_PTHREAD([], [AC_MSG_ERROR([Could not configure pthread support])])

# Make sure the C compiler supports weak symbols
AX_SYS_WEAK_ALIAS
AS_IF([test "x$ax_cv_sys_weak_alias" = "xno"],
  [AC_MSG_ERROR([Your platform doesn't support weak symbols.])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_TYPEOF
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Detect warning flags supported by the C compiler and append them to
# WARN_CFLAGS.
m4_define([WARN_FLAGS_LIST], [ dnl
  -Wall dnl
  -Wextra dnl
  -Wmissing-prototypes dnl
  -Wmissing-declarations dnl
  -Wnull-dereference dnl
  -Wundef dnl
  -Wshadow dnl
  -Wjump-misses-init dnl
  -Wsuggest-attribute=format dnl
  -Wtautological-constant-out-of-range-compare dnl
  -Wnested-externs dnl
  -Wwrite-strings dnl
  -Wformat=2 dnl
  -Wstrict-aliasing dnl
  -Wmissing-noreturn dnl
  -Winit-self dnl
  -Wduplicated-cond dnl
  -Wduplicated-branches dnl
  -Wlogical-op dnl
  dnl These would require reworking the tracepoint macros
  dnl-Wredundant-decls dnl
  -Wno-sign-compare dnl
  -Wno-missing-field-initializers dnl
  -Wno-null-dereference dnl
  -Wno-gnu dnl Disable warnings for GNU extensions on Clang
])

# Pass -Werror as an extra flag during the test: this is needed to make the
# -Wunknown-warning-option diagnostic fatal with clang.
AC_LANG_PUSH([C])
AX_APPEND_COMPILE_FLAGS([WARN_FLAGS_LIST], [WARN_CFLAGS], [-Werror])
AC_LANG_POP([C])

# The test used in AX_APPEND_COMPILE_FLAGS, generated using AC_LANG_PROGRAM, is
# written in such a way that it triggers warnings with the following warning
# flags.  So they would always end up disabled if we put them there, because
# the test program would not build.
#
# Enable them here unconditionally.  They are supported by GCC >= 4.8 and by
# Clang >= 3.3 (required by the project) and are only valid for C code.
WARN_CFLAGS="${WARN_CFLAGS} -Wold-style-definition -Wstrict-prototypes"

# Disable 'strict aliasing' if the compiler supports it.
AC_LANG_PUSH([C])
AX_APPEND_COMPILE_FLAGS([-fno-strict-aliasing], [OPT_CFLAGS], [-Werror])
AC_LANG_POP([C])


##                     ##
## C++ compiler checks ##
##                     ##

# Find an optional C++11 compiler without GNU extensions (-std=c++11)
AX_CXX_COMPILE_STDCXX([11], [noext], [optional])

AS_IF([test "$HAVE_CXX11" = "1"], [
  # Pass -Werror as an extra flag during the test: this is needed to make the
  # -Wunknown-warning-option diagnostic fatal with clang.
  AC_LANG_PUSH([C++])
  AX_APPEND_COMPILE_FLAGS([WARN_FLAGS_LIST -Wno-undef -Wno-duplicated-branches], [WARN_CXXFLAGS], [-Werror])
  AC_LANG_POP([C++])
])


##               ##
## Header checks ##
##               ##

AC_HEADER_STDBOOL
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  dlfcn.h \
  fcntl.h \
  float.h \
  limits.h \
  linux/perf_event.h \
  locale.h \
  stddef.h \
  sys/socket.h \
  sys/time.h \
  wchar.h \
])

# Check for dlinfo() by testing for RTLD_DI_LINKMAP in dlfcn.h
AS_IF([test "x$ac_cv_header_dlfcn_h" = "xyes"], [
  AC_CHECK_DECL([RTLD_DI_LINKMAP], [], [], [[#include <dlfcn.h>]])
])


##                 ##
## Programs checks ##
##                 ##

AM_PROG_AR
AC_PROG_SED
AC_PROG_GREP
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_MAKE_SET
AC_CHECK_PROGS([ASCIIDOC], [asciidoc])
AC_CHECK_PROGS([CMAKE], [cmake])
AC_CHECK_PROGS([FOLD], [fold])
AC_CHECK_PROGS([XMLTO], [xmlto])

AM_PATH_PYTHON([2.7], [], [PYTHON=""])

# Initialize and configure libtool
LT_INIT([disable-static])


##                ##
## Library checks ##
##                ##

AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MMAP
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([ \
  atexit \
  clock_gettime \
  ftruncate \
  getpagesize \
  gettid \
  gettimeofday \
  localeconv \
  memchr \
  memmove \
  memset \
  mkdir \
  munmap \
  realpath \
  sched_getcpu \
  socket \
  strchr \
  strdup \
  strerror \
  strtol \
  strtoul \
  sysconf \
])

# AC_FUNC_MALLOC causes problems when cross-compiling.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC

# Check for pthread_setname_np and its signature
AE_PTHREAD_SETNAME_NP
AE_PTHREAD_GETNAME_NP

# Check dor dlopen() in -ldl or -lc
AC_CHECK_LIB([dl], [dlopen], [
  libdl_name=dl
  DL_LIBS="-ldl"
], [
  # dlopen not found in libdl, check in libc
  AC_CHECK_LIB([c], [dlopen], [
    libdl_name=c
    DL_LIBS="-lc"
  ], [
    AC_MSG_ERROR([Cannot find dlopen in libdl nor libc. Use [LDFLAGS]=-Ldir to specify their location.])
  ])
])
AC_SUBST(DL_LIBS)

# Check if libdl has dlmopen()
AC_CHECK_LIB([$libdl_name], [dlmopen], [
  AC_DEFINE([HAVE_DLMOPEN], [1], [Define to 1 if dlmopen is available.])
])

# Require URCU >= 0.12 for DEFINE_URCU_TLS_INIT
PKG_CHECK_MODULES([URCU], [liburcu >= 0.12])


##                 ##
## User variables  ##
##                 ##

# Additional variables captured during ./configure

AC_ARG_VAR([CLASSPATH], [Java class path])
AC_ARG_VAR([JAVACFLAGS], [Java compiler flags])
AC_ARG_VAR([JAVAC], [Java compiler])
AC_ARG_VAR([JAVAFLAGS], [Java VM flags])
AC_ARG_VAR([JAVA], [Java VM])
AC_ARG_VAR([JAVAPREFIX], [prefix where Java runtime is installed])


##                              ##
## Optional features selection ##
##                              ##

# numa integration
# Enabled by default, except on some platforms
AE_FEATURE_DEFAULT_ENABLE
AE_FEATURE([numa],[disable NUMA support])

# Java JNI interface library
# Disabled by default
AE_FEATURE_DEFAULT_DISABLE
AE_FEATURE([jni-interface], [build JNI interface between C and Java])

# Build the Java Logging API agent
# Disabled by default
AE_FEATURE_DEFAULT_DISABLE
AE_FEATURE([java-agent-jul],[build the LTTng UST Java agent with JUL support])

# Build the Java Log4j 1.x agent
# Disabled by default
AE_FEATURE_DEFAULT_DISABLE
AE_FEATURE([java-agent-log4j],[build the LTTng UST Java agent with Log4j 1.x support (deprecated)])

# Build the Java Log4j 2.x agent
# Disabled by default
AE_FEATURE_DEFAULT_DISABLE
AE_FEATURE([java-agent-log4j2],[build the LTTng UST Java agent with Log4j 2.x support])

# Build both Java agents
# Disabled by default
AE_FEATURE_DEFAULT_DISABLE
AE_FEATURE([java-agent-all],[build the LTTng UST Java agent with all supported backends])

# Build the Python agent
# Disabled by default
AE_FEATURE_DEFAULT_DISABLE
AE_FEATURE([python-agent],[build the LTTng UST Python agent])

# Build the examples
# Disabled by default
AE_FEATURE_DEFAULT_ENABLE
AE_FEATURE([examples],[Do not build and install examples])

# Man pages
# Enabled by default
AE_FEATURE_DEFAULT_ENABLE
AE_FEATURE([man-pages],[Do not build and install man pages (already built in a distributed tarball)])

# Systemtap sdt.h integration
# Disabled by default
AC_ARG_WITH([sdt],
  [AS_HELP_STRING([--with-sdt], [provide SystemTap integration via sdt.h [default=no]])]
)

# Override the default runtime directory
AC_ARG_WITH([lttng-system-rundir], [
AS_HELP_STRING([--with-lttng-system-rundir], [Location of the system directory where LTTng-UST expects the system-wide lttng-sessiond runtime files. The default is "/var/run/lttng".]),
], [
  lttng_system_rundir="$withval"
], [
  lttng_system_rundir="/var/run/lttng"
])


##                                          ##
## Check for conflicting features selection ##
##                                          ##

AE_IF_FEATURE_DISABLED([shared], [
  AC_MSG_ERROR(LTTng-UST requires shared libraries to be enabled)
])

AE_IF_FEATURE_ENABLED([static], [
  AC_MSG_ERROR(Static linking LTTng-UST is currently unsupported)
])

AE_IF_FEATURE_ENABLED([java-agent-all], [
  AE_FEATURE_ENABLE([java-agent-jul])
  AE_FEATURE_ENABLE([java-agent-log4j])
  AE_FEATURE_ENABLE([java-agent-log4j2])
])


##                                          ##
## Check for optional features dependencies ##
##                                          ##

# The numa integration requires libnuma
AE_IF_FEATURE_ENABLED([numa], [
  AC_CHECK_LIB([numa], [numa_available], [
    AC_DEFINE([HAVE_LIBNUMA], [1], [Define to 1 if libnuma is available.])
  ], [
    AC_MSG_ERROR([dnl
libnuma is not available. Please either install it (e.g. libnuma-dev) or use
[LDFLAGS]=-Ldir to specify the right location, or use --disable-numa configure
argument to disable NUMA support.
    ])
  ])
])

# The JNI interface and Java Agents require a working Java JDK
AS_IF([AE_IS_FEATURE_ENABLED([jni-interface]) || AE_IS_FEATURE_ENABLED([java-agent-jul]) || \
    AE_IS_FEATURE_ENABLED([java-agent-log4j]) || AE_IS_FEATURE_ENABLED([java-agent-log4j2])], [
  AX_PROG_JAVAC
  AX_PROG_JAVA
  AX_PROG_JAR

  # Get the CPPFLAGS required to build jni libraries
  AX_JNI_INCLUDE_DIR
  for jni_include_dir in $JNI_INCLUDE_DIRS; do
    JNI_CPPFLAGS="$JNI_CPPFLAGS -I$jni_include_dir"
  done

  # Check for javah and jni.h
  saved_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $JNI_CPPFLAGS"
  AX_PROG_JAVAH
  CPPFLAGS="$saved_CPPFLAGS"
])

# The log4j 1.x agent requires the log4j jar in the classpath
AE_IF_FEATURE_ENABLED([java-agent-log4j], [
  AX_CHECK_CLASS([org.apache.log4j.Logger])
  AS_IF([test "x$ac_cv_class_org_apache_log4j_Logger" = "xno"], [
    AC_MSG_ERROR([dnl
The UST Java agent support for log4j was requested but the Log4j classes were
not found. Please specify the location of the Log4j jar via the Java CLASSPATH
environment variable, e.g. ./configure CLASSPATH="/path/to/log4j.jar"

Current CLASSPATH: "$CLASSPATH"
    ])
  ])
])

# The log4j 2.x agent requires the log4j core and api jars in the classpath
AE_IF_FEATURE_ENABLED([java-agent-log4j2], [
  AX_CHECK_CLASS([org.apache.logging.log4j.Logger])
  AX_CHECK_CLASS([org.apache.logging.log4j.core.Core])
  AS_IF([test "x$ac_cv_class_org_apache_logging_log4j_Logger" = "xno" || test "x$ac_cv_class_org_apache_logging_log4j_core_Core" = "xno"], [
    AC_MSG_ERROR([dnl
The UST Java agent support for log4j was requested but the Log4j classes were
not found. Please specify the location of the Log4j API and core 2.x jars via the Java CLASSPATH
environment variable, e.g. ./configure CLASSPATH="/path/to/log4j-core.jar:/path/to/log4j-api.jar"

Current CLASSPATH: "$CLASSPATH"
    ])
  ])
])

# The python agent requires a python interpreter
AE_IF_FEATURE_ENABLED([python-agent], [
  AS_IF([test "x$PYTHON" = "x"], [
    AC_MSG_ERROR([dnl
Cannot find a suitable python interpreter. You can override it with the PYTHON
environment variable.
    ])
  ])

  AX_COMPARE_VERSION(["$PYTHON_VERSION"], [ge], ["3.12"], [
    have_python_312_or_greater=yes
    AC_MSG_CHECKING([for python setuptools])
    AS_IF(["$PYTHON" -c "import setuptools" 2>/dev/null], [
      AC_MSG_RESULT([yes])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([Python >= 3.12 removed 'distutils', the 'setuptools' module needs to be installed for the selected interpreter.])
    ])
  ])
])

# Check for asciidoc and xmlto if we enabled building the man pages.
AE_IF_FEATURE_ENABLED([man-pages], [
  AS_IF([test "x$ASCIIDOC" = "x" || test "x$XMLTO" = "x"], [
    AE_IF_IN_GIT_REPO([
      # This is an error because we're in the Git repo, which
      # means the man pages are not already generated for us,
      # thus asciidoc/xmlto are required because we were asked
      # to build the man pages.
      AC_MSG_ERROR([dnl
Both asciidoc and xmlto are needed to build the LTTng-UST man pages. Use
--disable-man-pages to disable building the man pages, in which case
they will not be installed.
      ])
    ], [
      # Only warn here: since we're in the tarball, the man
      # pages should already be generated at this point, thus
      # asciidoc/xmlto are not strictly required.
      warn_prebuilt_man_pages=yes
    ])
  ], [
    have_asciidoc_xmlto=yes
  ])
])

AS_IF([test "x$with_sdt" = "xyes"], [
  AC_MSG_CHECKING([STAP_PROBEV()])
  AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
    #define SDT_USE_VARIADIC
    #include <sys/sdt.h>
    void fct(void)
    {
      STAP_PROBEV(provider,name,1,2,3,4,5,6,7,8,9,10);
    }
  ]])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([LTTNG_UST_HAVE_SDT_INTEGRATION], [1], [SystemTap integration via sdt.h])
  ], [
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([dnl
The sdt.h integration was requested but the STAP_PROBEV define cannot be used.
Make sure it is installed, and up to date, or use CPPFLAGS=-I/path/ to specify
a non-standard path to sys/sdt.h
    ])
  ])
])


##                                                                    ##
## Set defines for optional features conditionnals in the source code ##
##                                                                    ##

AC_DEFINE_UNQUOTED([LTTNG_SYSTEM_RUNDIR], ["$lttng_system_rundir"], [LTTng system runtime directory])

# Defined in include/lttng/ust-version.h
AC_DEFINE([LTTNG_UST_MAJOR_VERSION], ust_version_major, [LTTng UST major version])
AC_DEFINE([LTTNG_UST_MINOR_VERSION], ust_version_minor, [LTTng UST minor version])
AC_DEFINE([LTTNG_UST_PATCHLEVEL_VERSION], ust_version_patch, [LTTng UST patch version])
AC_DEFINE([LTTNG_UST_VERSION], ["]ust_version["], [LTTng UST version string])
AC_DEFINE([LTTNG_UST_LIB_SONAME_MAJOR], [ust_lib_version_current], [Major SONAME number of liblttng-ust])
AC_DEFINE([LTTNG_UST_CTL_LIB_SONAME_MAJOR], [ust_ctl_lib_version_current], [Major SONAME number of liblttng-ust-ctl])


##                                                                          ##
## Set automake variables for optional feature conditionnals in Makefile.am ##
##                                                                          ##

AM_CONDITIONAL([ENABLE_EXAMPLES], AE_IS_FEATURE_ENABLED([examples]))
AM_CONDITIONAL([ENABLE_GEN_TP_EXAMPLES], [test "x$PYTHON" != "x"])
AM_CONDITIONAL([ENABLE_JAVA_AGENT], AE_IS_FEATURE_ENABLED([java-agent-jul]) || AE_IS_FEATURE_ENABLED([java-agent-log4j]) || AE_IS_FEATURE_ENABLED([java-agent-log4j2]))
AM_CONDITIONAL([ENABLE_JAVA_AGENT_WITH_JUL], AE_IS_FEATURE_ENABLED([java-agent-jul]))
AM_CONDITIONAL([ENABLE_JAVA_AGENT_WITH_LOG4J], AE_IS_FEATURE_ENABLED([java-agent-log4j]))
AM_CONDITIONAL([ENABLE_JAVA_AGENT_WITH_LOG4J2], AE_IS_FEATURE_ENABLED([java-agent-log4j2]))
AM_CONDITIONAL([ENABLE_JAVA_AGENT_WITH_LOG4J_COMMON], AE_IS_FEATURE_ENABLED([java-agent-log4j]) || AE_IS_FEATURE_ENABLED([java-agent-log4j2]))
AM_CONDITIONAL([ENABLE_JNI_INTERFACE], AE_IS_FEATURE_ENABLED([jni-interface]))
AM_CONDITIONAL([ENABLE_MAN_PAGES], AE_IS_FEATURE_ENABLED([man-pages]))
AM_CONDITIONAL([ENABLE_NUMA], AE_IS_FEATURE_ENABLED([numa]))
AM_CONDITIONAL([ENABLE_PYTHON_AGENT], AE_IS_FEATURE_ENABLED([python-agent]))
AM_CONDITIONAL([ENABLE_UST_DL], [test "x$ac_cv_have_decl_RTLD_DI_LINKMAP" = "xyes"])
AM_CONDITIONAL([HAVE_ASCIIDOC_XMLTO], [test "x$have_asciidoc_xmlto" = "xyes"])
AM_CONDITIONAL([HAVE_CMAKE], [test "x$CMAKE" != "x"])
AM_CONDITIONAL([HAVE_CXX], [test "$HAVE_CXX11" = "1"])
AM_CONDITIONAL([HAVE_JAVAH], [test "x$JAVAH" != "x"])
AM_CONDITIONAL([HAVE_PERF_EVENT], [test "x$ac_cv_header_linux_perf_event_h" = "xyes"])
AM_CONDITIONAL([HAVE_PYTHON_312_OR_GREATER], [test "x$have_python_312_or_greater" = "xyes"])


##                                             ##
## Substitute variables for use in Makefile.am ##
##                                             ##

# Library versions for libtool
AC_SUBST([LTTNG_UST_LIBRARY_VERSION], ust_lib_version)
AC_SUBST([LTTNG_UST_CTL_LIBRARY_VERSION], ust_ctl_lib_version)

# Major soname for python-lttngust
AC_SUBST([LTTNG_UST_LIB_SONAME_MAJOR], [ust_lib_version_current])

AM_CFLAGS="$OPT_CFLAGS $WARN_CFLAGS $URCU_CFLAGS $PTHREAD_CFLAGS"
AC_SUBST(AM_CFLAGS)

AM_CXXFLAGS="$WARN_CXXFLAGS $URCU_CFLAGS $PTHREAD_CFLAGS"
AC_SUBST(AM_CXXFLAGS)

# The order in which the include folders are searched is important.
# The top_builddir should always be searched first in the event that a build
# time generated file is included.
AM_CPPFLAGS="-I\$(top_builddir)/include -I\$(top_srcdir)/include -I\$(top_builddir)/src -I\$(top_srcdir)/src -include common/config.h"
AC_SUBST(AM_CPPFLAGS)

AC_SUBST(JNI_CPPFLAGS)

# Used in man pages
AC_SUBST([LTTNG_UST_MAJOR_VERSION], ust_version_major)
AC_SUBST([LTTNG_UST_MINOR_VERSION], ust_version_minor)

##                                     ##
## Output files generated by configure ##
##                                     ##

# List of files to be generated from '.in' templates by AC_OUTPUT
AC_CONFIG_FILES([
  Makefile
  doc/examples/Makefile
  doc/Makefile
  doc/man/Makefile
  extras/Makefile
  include/Makefile
  src/common/Makefile
  src/lib/lttng-ust-common/Makefile
  src/lib/lttng-ust-ctl/Makefile
  src/lib/lttng-ust-cyg-profile/Makefile
  src/lib/lttng-ust-dl/Makefile
  src/lib/lttng-ust-fd/Makefile
  src/lib/lttng-ust-fork/Makefile
  src/lib/lttng-ust-java-agent/java/lttng-ust-agent-all/Makefile
  src/lib/lttng-ust-java-agent/java/lttng-ust-agent-common/Makefile
  src/lib/lttng-ust-java-agent/java/lttng-ust-agent-jul/Makefile
  src/lib/lttng-ust-java-agent/java/lttng-ust-agent-log4j/Makefile
  src/lib/lttng-ust-java-agent/java/lttng-ust-agent-log4j2/Makefile
  src/lib/lttng-ust-java-agent/java/Makefile
  src/lib/lttng-ust-java-agent/jni/common/Makefile
  src/lib/lttng-ust-java-agent/jni/jul/Makefile
  src/lib/lttng-ust-java-agent/jni/log4j/Makefile
  src/lib/lttng-ust-java-agent/jni/Makefile
  src/lib/lttng-ust-java-agent/Makefile
  src/lib/lttng-ust-java/Makefile
  src/lib/lttng-ust-libc-wrapper/Makefile
  src/lib/lttng-ust-pthread-wrapper/Makefile
  src/lib/lttng-ust-tracepoint/Makefile
  src/lib/lttng-ust/Makefile
  src/lib/lttng-ust-python-agent/Makefile
  src/lib/Makefile
  src/lib/lttng-ust-ctl.pc
  src/lib/lttng-ust.pc
  src/Makefile
  src/python-lttngust/lttngust/version.py
  src/python-lttngust/Makefile
  src/python-lttngust/setup.py
  tests/benchmark/Makefile
  tests/compile/api0/ctf-types/Makefile
  tests/compile/api0/hello.cxx/Makefile
  tests/compile/api0/hello/Makefile
  tests/compile/api0/hello-many/Makefile
  tests/compile/api0/Makefile
  tests/compile/api0/same_line_tracepoint/Makefile
  tests/compile/api1/ust-fields/Makefile
  tests/compile/api1/hello.cxx/Makefile
  tests/compile/api1/hello/Makefile
  tests/compile/api1/hello-many/Makefile
  tests/compile/api1/Makefile
  tests/compile/api1/same_line_tracepoint/Makefile
  tests/compile/api1/test-app-ctx/Makefile
  tests/compile/Makefile
  tests/Makefile
  tests/regression/abi0-conflict/Makefile
  tests/regression/Makefile
  tests/unit/gcc-weak-hidden/Makefile
  tests/unit/libcommon/Makefile
  tests/unit/libmsgpack/Makefile
  tests/unit/libringbuffer/Makefile
  tests/unit/Makefile
  tests/unit/pthread_name/Makefile
  tests/unit/snprintf/Makefile
  tests/unit/ust-elf/Makefile
  tests/unit/ust-error/Makefile
  tests/unit/ust-utils/Makefile
  tests/utils/Makefile
  tools/Makefile
])

AC_OUTPUT


##                                    ##
## Mini-report on what will be built. ##
##                                    ##

AE_PPRINT_INIT
AE_PPRINT_SET_INDENT(1)
AE_PPRINT_SET_TS(38)

AS_ECHO
AS_IF([test -n "ust_version_name"], [
  AS_ECHO("${AE_PPRINT_COLOR_BLDBLU}LTTng-ust $PACKAGE_VERSION \"ust_version_name\"$AE_PPRINT_COLOR_RST")
], [
  AS_ECHO("${AE_PPRINT_COLOR_BLDBLU}LTTng-ust $PACKAGE_VERSION")
])

AS_ECHO

AS_IF([test -n "ust_version_description"], [
  AS_IF([test -n "$FOLD"], [
    AS_ECHO("`AS_ECHO(["ust_version_description"]) | $FOLD -s`")
  ], [
    AS_ECHO(["ust_version_description"])
  ])
  AS_ECHO
])

AE_PPRINT_SUBTITLE([System])

AE_PPRINT_PROP_STRING([Target architecture], $host_cpu)

AS_IF([test "x$unsupported_arch" = "xyes"],[
       AE_PPRINT_WARN([Your architecture ($host_cpu) is unsupported, using safe default of no unaligned access.])
])

AS_ECHO
AE_PPRINT_SUBTITLE([Features])
AE_PPRINT_SET_INDENT(1)

test "x$with_sdt" = "xyes" && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([sdt.h integration], $value, [use --with-sdt])

AE_IS_FEATURE_ENABLED([java-agent-jul]) && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([Java agent (JUL support)], $value, [use --enable-java-agent-jul])

AE_IS_FEATURE_ENABLED([java-agent-log4j]) && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([Java agent (Log4j 1.x support (deprecated))], $value, [use --enable-java-agent-log4j])

AE_IS_FEATURE_ENABLED([java-agent-log4j2]) && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([Java agent (Log4j 2.x support)], $value, [use --enable-java-agent-log4j2])

AE_IS_FEATURE_ENABLED([jni-interface]) && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([JNI interface (JNI)], $value, [use --enable-jni-interface])

AE_IS_FEATURE_ENABLED([python-agent]) && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([Python agent], $value, [use --enable-python-agent])

test "x$ac_cv_header_linux_perf_event_h" = "xyes" && value=1 || value=0
AE_PPRINT_PROP_BOOL_CUSTOM([Perf event integration], $value)

AE_IS_FEATURE_ENABLED([numa]) && value=1 || value=0
AE_PPRINT_PROP_BOOL([NUMA], $value)

AS_ECHO
AE_PPRINT_SET_INDENT(0)

AE_IS_FEATURE_ENABLED([examples]) && value=1 || value=0
AE_PPRINT_PROP_BOOL([Build and install examples], $value, $AE_PPRINT_COLOR_SUBTITLE)

# man pages build enabled/disabled
m4_pushdef([build_man_pages_msg], [Build and install man pages])

AE_IF_FEATURE_ENABLED([man-pages], [
  AE_IF_IN_GIT_REPO([
    AE_PPRINT_PROP_BOOL([build_man_pages_msg], 1, $AE_PPRINT_COLOR_SUBTITLE)
  ], [
    AS_IF([test "x$have_asciidoc_xmlto" = "xyes"], [
      AE_PPRINT_PROP_BOOL([build_man_pages_msg], 1, $AE_PPRINT_COLOR_SUBTITLE)
    ], [
      AE_PPRINT_PROP_STRING([build_man_pages_msg],
        [${AE_PPRINT_COLOR_BLDGRN}yes (already built)],
        $AE_PPRINT_COLOR_SUBTITLE)
    ])
  ])
], [
  AE_PPRINT_PROP_BOOL([build_man_pages_msg], 0, $AE_PPRINT_COLOR_SUBTITLE)
])

m4_popdef([build_man_pages_msg])

AE_PPRINT_SET_INDENT(1)

report_bindir="`eval eval echo $bindir`"
report_libdir="`eval eval echo $libdir`"

# Print the bindir and libdir this `make install' will install into.
AS_ECHO
AE_PPRINT_SUBTITLE([Install directories])
AE_PPRINT_PROP_STRING([Binaries], [$report_bindir])
AE_PPRINT_PROP_STRING([Libraries], [$report_libdir])

AS_ECHO
AE_PPRINT_SUBTITLE([System directories])

AE_PPRINT_PROP_STRING([lttng-sessiond rundir], [$lttng_system_rundir])

AE_PPRINT_SET_INDENT(0)

AS_IF([test "x$warn_prebuilt_man_pages" = "xyes" ], [
  AS_ECHO
  AE_PPRINT_WARN([dnl
Both asciidoc and xmlto are needed to build the LTTng-UST man pages.

Note that the man pages are already built in this distribution tarball,
therefore asciidoc and xmlto are only needed if you intend to modify
their sources.

Use --disable-man-pages to completely disable building and installing
the man pages.])
])

# vim: shiftwidth=2 softtabstop=2 expandtab
