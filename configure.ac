#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([lttng-ust],[2.6.0-rc1],[mathieu dot desnoyers at efficios dot com])

# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# This is the library version of liblttng-ust.
AC_SUBST([LTTNG_UST_LIBRARY_VERSION], [0:0:0])
# note: remember to update tracepoint.h dlopen() to match this version
# number. TODO: eventually automate by exporting the major number.

# This is the library version of liblttng-ust-ctl, used internally by
# liblttng-ust, lttng-sessiond, and lttng-consumerd.
AC_SUBST([LTTNG_UST_CTL_LIBRARY_VERSION], [2:0:0])

AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([include/lttng/tracepoint.h])

# Configuration options, which will be installed in the config.h
AC_CONFIG_HEADERS([config.h include/lttng/ust-config.h])
AH_TEMPLATE([LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS], [Use efficient unaligned access.])
AH_TEMPLATE([LTTNG_UST_HAVE_SDT_INTEGRATION], [SystemTap integration via sdt.h])
AH_TEMPLATE([LTTNG_UST_HAVE_PERF_EVENT], [Perf event integration via perf_event.h])

# Compute minor/major/patchlevel version numbers
AC_PROG_SED
major_version=$(echo AC_PACKAGE_VERSION | sed 's/^\([[0-9]]\)*\.[[0-9]]*\.[[0-9]]*.*$/\1/')
minor_version=$(echo AC_PACKAGE_VERSION | sed 's/^[[0-9]]*\.\([[0-9]]*\)\.[[0-9]]*.*$/\1/')
patchlevel_version=$(echo AC_PACKAGE_VERSION | sed 's/^[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\).*$/\1/')
AC_SUBST([MAJOR_VERSION], [$major_version])
AC_SUBST([MINOR_VERSION], [$minor_version])
AC_SUBST([PATCHLEVEL_VERSION], [$patchlevel_version])
AC_DEFINE_UNQUOTED([VERSION_MAJOR], $major_version, [UST major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], $minor_version, [UST minor version number])
AC_DEFINE_UNQUOTED([VERSION_PATCHLEVEL], $patchlevel_version, [UST patchlevel version number])

version_name="Gaia"
version_description="From Benelux brewery in Montreal, the Gaia is a witbier with a cloudy light amber ale color. Aroma of coriander with floral hay notes is enchanting. Taste is also dominated by the very floral coriander note and some medium sweet malt notes."

AC_DEFINE_UNQUOTED([VERSION_NAME], ["$version_name"], [UST version name])
AC_DEFINE_UNQUOTED([VERSION_DESCRIPTION], ["$version_description"], [UST version description])

AC_PROG_GREP
AC_PROG_LN_S
# libtool link_all_deplibs fixup. See http://bugs.lttng.org/issues/321.
AC_ARG_ENABLE(libtool-linkdep-fixup,
	AS_HELP_STRING([--disable-libtool-linkdep-fixup],
			[disable the libtool fixup for linking all dependent libraries (link_all_deplibs)]),
	libtool_fixup=$enableval,
	libtool_fixup=yes)

AS_IF([test "x$libtool_fixup" = "xyes"],
	    [
	    libtool_m4="$srcdir/config/libtool.m4"
	    libtool_flag_pattern=".*link_all_deplibs\s*,\s*\$1\s*)"
	    AC_MSG_CHECKING([for occurence(s) of link_all_deplibs = no in $libtool_m4])
	    libtool_flag_pattern_count=$(grep -c "$libtool_flag_pattern\s*=\s*no" $libtool_m4)
	    AS_IF([test $libtool_flag_pattern_count -ne 0],
	    [
		  AC_MSG_RESULT([$libtool_flag_pattern_count])
		  AC_MSG_WARN([the detected libtool will not link all dependencies, forcing link_all_deplibs = unknown])
		  sed -i "s/\($libtool_flag_pattern\)\s*=\s*no/\1=unknown/g" $libtool_m4
		  ],
		  [
		  AC_MSG_RESULT([none])
		  ])
	    ])

AM_CONDITIONAL([NO_SHARED], [test "x$enable_shared" = "xno"])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
LT_INIT

# rw_PROG_CXX_WORKS
# Check whether the C++ compiler works.
AC_CACHE_CHECK([whether the C++ compiler works],
		[rw_cv_prog_cxx_works],
		[AC_LANG_PUSH([C++])
		AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
				[check_cxx_designated_initializers=yes],
				[rw_cv_prog_cxx_works=no])
		if test "$check_cxx_designated_initializers" = "yes"; then
			AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
				struct foo { int a; int b; };
				void fct(void)
				{
					struct foo f = { .a = 0, .b = 1 };
				}
			]])],[
				rw_cv_prog_cxx_works=yes
			],[
				rw_cv_prog_cxx_works=no
			])
		fi
		AC_LANG_POP([C++])])

AM_CONDITIONAL([CXX_WORKS], [test "x$rw_cv_prog_cxx_works" = "xyes"])

# Check if the compiler support weak symbols
AX_SYS_WEAK_ALIAS

if test "x${ax_cv_sys_weak_alias}" = "xno"; then
   AC_MSG_ERROR([Your platform doesn't support weak symbols.])
fi

## Checks for libraries.
AC_CHECK_LIB([dl], [dlopen],
[
	have_libdl=yes
],
[
	#libdl not found, check for dlopen in libc.
	AC_CHECK_LIB([c], [dlopen],
	[
		have_libc_dl=yes
	],
	[
		AC_MSG_ERROR([Cannot find dlopen in libdl nor libc. Use [LDFLAGS]=-Ldir to specify their location.])
	])
])
AM_CONDITIONAL([LTTNG_UST_BUILD_WITH_LIBDL], [test "x$have_libdl" = "xyes"])
AM_CONDITIONAL([LTTNG_UST_BUILD_WITH_LIBC_DL], [test "x$have_libc_dl" = "xyes"])

AC_CHECK_LIB([pthread], [pthread_create])

# Check for dlfcn.h
AC_CHECK_HEADER([dlfcn.h])
AS_IF([test "x${ac_cv_header_dlfcn_h}" = "xyes"],
	[AC_CHECK_DECLS([RTLD_DI_LINKMAP],,,
		[#define _GNU_SOURCE /* Required on Linux to get GNU extensions */
		#include <dlfcn.h>])
	],
	[ac_cv_have_decl_RTLD_DI_LINKMAP="no"])
AM_CONDITIONAL([HAVE_DLINFO], [test "x${ac_cv_have_decl_RTLD_DI_LINKMAP}" = "xyes"])

# Checks for header files.
#AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
#AC_TYPE_INT16_T
#AC_TYPE_INT32_T
#AC_TYPE_INT64_T
#AC_TYPE_INT8_T
#AC_TYPE_PID_T
#AC_TYPE_SIZE_T
#AC_TYPE_SSIZE_T
#AC_TYPE_UINT16_T
#AC_TYPE_UINT32_T
#AC_TYPE_UINT64_T
#AC_TYPE_UINT8_T
#AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gettimeofday munmap socket strerror strtol sched_getcpu sysconf])

CFLAGS="-Wall $CFLAGS"

# URCU

# urcu - check if we just find the headers it out of the box.
AC_CHECK_HEADERS([urcu-bp.h], [], [AC_MSG_ERROR([Cannot find [URCU] headers (urcu-bp.h). Use [CPPFLAGS]=-Idir to specify their location.
This error can also occur when the liburcu package's configure script has not been run.])])

# urcu-cds - check that URCU Concurrent Data Structure lib is available to compilation
# Part of Userspace RCU library 0.7.2 or better.
AC_CHECK_LIB([urcu-cds], [_cds_lfht_new], [], [AC_MSG_ERROR([Cannot find
liburcu-cds lib, part of Userspace RCU 0.7 or better. Use [LDFLAGS]=-Ldir to specify its location.])])

AC_MSG_CHECKING([caa_likely()])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <urcu/compiler.h>
void fct(void)
{
	if (caa_likely(1)) {
	}
}
]])],[
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([Please upgrade your version of liburcu to 0.6.6 or better])

])

# urcu - check that URCU lib is available to compilation
AC_CHECK_LIB([urcu-bp], [synchronize_rcu_bp], [], [AC_MSG_ERROR([Cannot find liburcu-bp lib. Use [LDFLAGS]=-Ldir to specify its location.])])

# urcu - check that URCU lib is at least version 0.6
AC_CHECK_LIB([urcu-bp], [call_rcu_bp], [], [AC_MSG_ERROR([liburcu 0.6 or newer is needed, please update your version or use [LDFLAGS]=-Ldir to specify the right location.])])

# optional linux/perf_event.h
AC_CHECK_HEADERS([linux/perf_event.h], [have_perf_event=yes], [])

# Perf event counters are only supported on x86 so far.
AC_MSG_CHECKING([UST support for architecture perf event counters])
case $host_cpu in
changequote(,)dnl
	i[3456]86)
changequote([,])dnl
	UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS=yes;;
	x86_64) UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS=yes;;
	amd64) UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS=yes;;
	*) UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS=no;;
esac
AC_MSG_RESULT([$UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS])

AM_CONDITIONAL([HAVE_PERF_EVENT], [test "x$have_perf_event" = "xyes" -a "x$UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS" = "xyes"])

if test "x$have_perf_event" = "xyes" -a "x$UST_SUPPORT_FOR_ARCH_PERF_EVENT_COUNTERS" = "xyes"; then
AC_DEFINE([LTTNG_UST_HAVE_PERF_EVENT], [1])
fi

AC_MSG_CHECKING([host system alignment requirements])
case $host_cpu in
changequote(,)dnl
	i[3456]86)
changequote([,])dnl
	  ;;
	x86_64) ;;
	amd64) ;;
	powerpc) ;;
	ppc64) ;;
	ppc64le) ;;
	powerpc64) ;;
	powerpc64le) ;;
	s390) NO_UNALIGNED_ACCESS=1 ;;
	s390x) NO_UNALIGNED_ACCESS=1 ;;
        arm*) NO_UNALIGNED_ACCESS=1 ;;
	aarch64) NO_UNALIGNED_ACCESS=1 ;;
	mips*) NO_UNALIGNED_ACCESS=1 ;;
	tile*) NO_UNALIGNED_ACCESS=1 ;;
	*) AC_MSG_ERROR([unable to detect alignment requirements (unsupported architecture ($host_cpu)?)]) ;;
esac
AC_MSG_RESULT([$host_cpu])

if test x$NO_UNALIGNED_ACCESS = x ; then
AC_DEFINE([LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS], [1])
fi

# Check for JNI header files if requested
AC_ARG_ENABLE([jni-interface],
	[AS_HELP_STRING([--enable-jni-interface],[build JNI interface between C and Java. Needs Java include files [default=no]])],
	[jni_interface=$withval],
	[jni_interface=no]
)

AM_CONDITIONAL([BUILD_JNI_INTERFACE], [test "x$jni_interface" = "xyes"])


AC_ARG_ENABLE([java-agent-jul],
	[AS_HELP_STRING([--enable-java-agent-jul],[build the LTTng UST Java agent with JUL support [default=no]])],
	[java_agent_jul=$enableval],
	[java_agent_jul=no]
)

AC_ARG_ENABLE([java-agent-log4j],
	[AS_HELP_STRING([--enable-java-agent-log4j],[build the LTTng UST Java agent with Log4j support [default=no]])],
	[java_agent_log4j=$enableval],
	[java_agent_log4j=no]
)

AC_ARG_ENABLE([java-agent-all],
	[AS_HELP_STRING([--enable-java-agent-all],[build the LTTng UST Java agent with all supported backends [default=no]])],
	[java_agent_jul=$enableval
	 java_agent_log4j=$enableval],
	[:]
)


AM_CONDITIONAL([BUILD_JAVA_AGENT], [test "x$java_agent_jul" = "xyes" || test "x$java_agent_log4j" = "xyes"])
AM_CONDITIONAL([BUILD_JAVA_AGENT_WITH_JUL], [test "x$java_agent_jul" = "xyes"])
AM_CONDITIONAL([BUILD_JAVA_AGENT_WITH_LOG4J], [test "x$java_agent_log4j" = "xyes"])

if test "x$jni_interface" = "xyes" || test "x$java_agent_jul" = "xyes" || test "x$java_agent_log4j" = "xyes"; then
  AX_JAVA_OPTIONS
  AX_PROG_JAVAC
  AX_PROG_JAVA
  AX_PROG_JAR

  AX_JNI_INCLUDE_DIR
  for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
  do
	CPPFLAGS="$CPPFLAGS -I$JNI_INCLUDE_DIR"
  done

  AX_PROG_JAVAH
fi

if test "x$java_agent_log4j" = "xyes"; then
  AX_CHECK_CLASSPATH

  AX_CHECK_CLASS(org.apache.log4j.Logger)

  if test "x$ac_cv_class_org_apache_log4j_Logger" = "xno"; then
     AC_MSG_ERROR([The UST Java agent support for log4j was requested but the Log4j classes were not found. Please specify the location of the Log4j jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/log4j.jar"])
  fi
fi

# Option to build the python agent
AC_ARG_ENABLE([python-agent],
	[AS_HELP_STRING([--enable-python-agent],[build the LTTng UST Python agent [default=no]])],
    [python_agent=$enableval],
	[:]
)
AM_CONDITIONAL([BUILD_PYTHON_AGENT], [test "x$python_agent" = "xyes"])

# sdt.h integration
AC_ARG_WITH([sdt],
	[AS_HELP_STRING([--with-sdt],[provide SystemTap integration via sdt.h [default=no]])],
	[with_sdt=$withval],
	[with_sdt="no"]
)

AS_IF([test "x$with_sdt" = "xyes"],[
	AC_MSG_CHECKING([STAP_PROBEV()])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
	#define SDT_USE_VARIADIC
	#include <sys/sdt.h>
	void fct(void)
	{
		STAP_PROBEV(provider,name,1,2,3,4,5,6,7,8,9,10);
	}
	]])],[
		AC_MSG_RESULT([yes])
		AC_DEFINE([LTTNG_UST_HAVE_SDT_INTEGRATION], [1])
	],[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([The sdt.h integration was requested but the STAP_PROBEV define cannot be used. Make sure it is installed, and up to date, or use CPPFLAGS=-I/path/ to specify a non-standard path to sys/sdt.h])
	])
])

AC_MSG_CHECKING([whether shared libraries are enabled])
AS_IF([test "x$enable_shared" = "xyes"],
	[
		AC_MSG_RESULT([yes])
	],
	[
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([LTTng-UST requires shared libraries to be enabled])
	])

AC_ARG_WITH([lttng-system-rundir],
	AS_HELP_STRING([--with-lttng-system-rundir],
	[Location of the system directory where LTTng-UST expects the system-wide lttng-sessiond runtime files. The default is "/var/run/lttng".]),
	[lttng_system_rundir="$withval"],
	[lttng_system_rundir="/var/run/lttng"])
AC_DEFINE_UNQUOTED([LTTNG_SYSTEM_RUNDIR], ["$lttng_system_rundir"],
	[LTTng system runtime directory])

AM_PATH_PYTHON([2.7],BUILD_GEN_TP_EXAMPLES=1,[:])
AM_CONDITIONAL([BUILD_GEN_TP_EXAMPLES], [test $BUILD_GEN_TP_EXAMPLES], [Build examples requiring lttng-gen-tp])

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/examples/Makefile
	include/Makefile
	include/lttng/ust-version.h
	snprintf/Makefile
	libringbuffer/Makefile
	liblttng-ust-comm/Makefile
	liblttng-ust/Makefile
	liblttng-ust-ctl/Makefile
	liblttng-ust-fork/Makefile
	liblttng-ust-dl/Makefile
	liblttng-ust-java/Makefile
	liblttng-ust-java-agent/Makefile
	liblttng-ust-java-agent/java/Makefile
	liblttng-ust-java-agent/jni/Makefile
	liblttng-ust-java-agent/jni/jul/Makefile
	liblttng-ust-java-agent/jni/log4j/Makefile
	liblttng-ust-libc-wrapper/Makefile
	liblttng-ust-cyg-profile/Makefile
	liblttng-ust-python-agent/Makefile
	tools/Makefile
	tests/Makefile
	tests/hello/Makefile
	tests/hello.cxx/Makefile
	tests/same_line_tracepoint/Makefile
	tests/snprintf/Makefile
	tests/benchmark/Makefile
	tests/utils/Makefile
	lttng-ust.pc
])

AC_OUTPUT

AS_ECHO()
AS_ECHO("Version name: $version_name")
AS_ECHO("$version_description")

# Report on the configuration options
AS_ECHO()
AS_ECHO("LTTng-UST will be built with the following options:")

AS_ECHO()

AS_ECHO_N("Java agent (JUL support): ")
AS_IF([test "x$java_agent_jul" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO_N("Java agent (Log4j support): ")
AS_IF([test "x$java_agent_log4j" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO_N("JNI interface (JNI): ")
AS_IF([test "x$jni_interface" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO_N("Python agent: ")
AS_IF([test "x$python_agent" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO_N("sdt.h integration:  ")
AS_IF([test "x$with_sdt" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO()
AS_ECHO("Type 'make' to compile.")

