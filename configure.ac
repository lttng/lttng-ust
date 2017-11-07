dnl Version infos
m4_define([V_MAJOR], [2])
m4_define([V_MINOR], [10])
m4_define([V_PATCH], [0])
m4_define([V_EXTRA], [rc1])
m4_define([V_NAME], [[KeKriek]])
m4_define([V_DESC], [[From Brasserie Dunham, a sour mashed golden wheat ale fermented with local sour cherries from Tougas orchards. Fresh sweet cherry notes with some tartness, lively carbonation with a dry finish.]])

m4_define([V_STRING], [V_MAJOR.V_MINOR.V_PATCH])
m4_ifdef([V_EXTRA], [m4_append([V_STRING], [-V_EXTRA])])

AC_PREREQ(2.59)
AC_INIT([lttng-ust], V_STRING, [mathieu dot desnoyers at efficios dot com], [], [https://lttng.org])

dnl Substitute minor/major/patchlevel version numbers
AC_SUBST([MAJOR_VERSION], [V_MAJOR])
AC_SUBST([MINOR_VERSION], [V_MINOR])
AC_SUBST([PATCHLEVEL_VERSION], [V_PATCH])

# Following the numbering scheme proposed by libtool for the library version
# http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
# This is the library version of liblttng-ust.
AC_SUBST([LTTNG_UST_LIBRARY_VERSION], [0:0:0])
# note: remember to update tracepoint.h dlopen() to match this version
# number. TODO: eventually automate by exporting the major number.

# This is the library version of liblttng-ust-ctl, used internally by
# liblttng-ust, lttng-sessiond, and lttng-consumerd.
AC_SUBST([LTTNG_UST_CTL_LIBRARY_VERSION], [4:0:0])

AC_CONFIG_HEADERS([config.h include/lttng/ust-config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([include/lttng/tracepoint.h])

AC_CANONICAL_TARGET
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([1.9 foreign dist-bzip2 no-dist-gzip tar-ustar])
AM_MAINTAINER_MODE([enable])

# Enable silent rules if available (Introduced in AM 1.11)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_REQUIRE_AUX_FILE([tap-driver.sh])

# Checks for C compiler
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
rw_PROG_CXX_WORKS
AM_CONDITIONAL([CXX_WORKS], [test "x$rw_cv_prog_cxx_works" = "xyes"])

# Check if the compiler support weak symbols
AX_SYS_WEAK_ALIAS

AS_IF([test "x${ax_cv_sys_weak_alias}" = "xno"], [
	AC_MSG_ERROR([Your platform doesn't support weak symbols.])
])

# Checks for programs.
AC_PROG_SED
AC_PROG_GREP
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_MAKE_SET
AC_CHECK_PROG([HAVE_CMAKE], [cmake], ["yes"])
AM_CONDITIONAL([HAVE_CMAKE], [test "x$HAVE_CMAKE" = "xyes"])

# libtool link_all_deplibs fixup. See http://bugs.lttng.org/issues/321.
AC_ARG_ENABLE([libtool-linkdep-fixup], [
AS_HELP_STRING([--disable-libtool-linkdep-fixup], [disable the libtool fixup for linking all dependent libraries (link_all_deplibs)])
], [
	libtool_fixup=$enableval
], [
	libtool_fixup=yes
])

AS_IF([test "x$libtool_fixup" = "xyes"], [
	libtool_m4="$srcdir/m4/libtool.m4"
	libtool_flag_pattern=".*link_all_deplibs\s*,\s*\$1\s*)"
	AC_MSG_CHECKING([for occurence(s) of link_all_deplibs = no in $libtool_m4])
	libtool_flag_pattern_count=$(grep -c "$libtool_flag_pattern\s*=\s*no" $libtool_m4)

	AS_IF([test $libtool_flag_pattern_count -ne 0], [
	AC_MSG_RESULT([$libtool_flag_pattern_count])
	AC_MSG_WARN([the detected libtool will not link all dependencies, forcing link_all_deplibs = unknown])
		$SED -i "s/\($libtool_flag_pattern\)\s*=\s*no/\1=unknown/g" $libtool_m4
	], [
		AC_MSG_RESULT([none])
	])
])
LT_INIT([disable-static])

AC_MSG_CHECKING([whether shared libraries are enabled])
AS_IF([test "x$enable_shared" = "xyes"], [
	AC_MSG_RESULT([yes])
], [
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([LTTng-UST requires shared libraries to be enabled])
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_CHECK_TYPES([ptrdiff_t])

AX_C___ATTRIBUTE__
AS_IF([test "x$ax_cv___attribute__" = "xyes"],
	[:],
	[AC_MSG_ERROR([The compiler does not support __attribute__ extensions])])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([ \
	atexit \
	clock_gettime \
	ftruncate \
	getpagesize \
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
	sysconf \
])

# AC_FUNC_MALLOC causes problems when cross-compiling.
#AC_FUNC_MALLOC

# Checks for header files.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([ \
	arpa/inet.h \
	fcntl.h \
	float.h \
	limits.h \
	locale.h \
	stddef.h \
	sys/socket.h \
	sys/time.h \
	wchar.h \
])

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
	[s390], [NO_UNALIGNED_ACCESS=1],
	[s390x], [NO_UNALIGNED_ACCESS=1],
	[arm*], [
		NO_UNALIGNED_ACCESS=1
		NO_NUMA=1
		],
	[aarch64*], [NO_UNALIGNED_ACCESS=1],
	[mips*], [NO_UNALIGNED_ACCESS=1],
	[tile*], [NO_UNALIGNED_ACCESS=1],
	[
		UNSUPPORTED_ARCH=1
		NO_UNALIGNED_ACCESS=1
	])

# Configuration options, which will be installed in the config.h
AH_TEMPLATE([LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS], [Use efficient unaligned access.])
AH_TEMPLATE([LTTNG_UST_HAVE_SDT_INTEGRATION], [SystemTap integration via sdt.h])
AH_TEMPLATE([LTTNG_UST_HAVE_PERF_EVENT], [Perf event integration via perf_event.h])

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen], [
	have_libdl=yes
	libdl_name=dl
], [
	#libdl not found, check for dlopen in libc.
	AC_CHECK_LIB([c], [dlopen], [
		have_libc_dl=yes
		libdl_name=c
	], [
		AC_MSG_ERROR([Cannot find dlopen in libdl nor libc. Use [LDFLAGS]=-Ldir to specify their location.])
	])
])

# Check if libdl has dlmopen support.
AH_TEMPLATE([HAVE_DLMOPEN], ["Define to 1 if dlmopen is available."])
AC_CHECK_LIB([$libdl_name], [dlmopen],
	[AC_DEFINE([HAVE_DLMOPEN], [1])]
)

AM_CONDITIONAL([LTTNG_UST_BUILD_WITH_LIBDL], [test "x$have_libdl" = "xyes"])
AM_CONDITIONAL([LTTNG_UST_BUILD_WITH_LIBC_DL], [test "x$have_libc_dl" = "xyes"])

AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([pthread], [pthread_setname_np],
	AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define to 1 if pthread_setname_np is available.]),
	AC_CHECK_LIB([pthread], [pthread_set_name_np],
		AC_DEFINE([HAVE_PTHREAD_SET_NAME_NP], [1], [Define to 1 if pthread_set_name_np is available.]),
		AC_MSG_RESULT([pthread setname/set_name not found.])))

# Check for dlfcn.h
AC_CHECK_HEADER([dlfcn.h])
AS_IF([test "x${ac_cv_header_dlfcn_h}" = "xyes"], [
	AC_CHECK_DECLS([RTLD_DI_LINKMAP], [], [], [
		#define _GNU_SOURCE /* Required on Linux to get GNU extensions */
		#include <dlfcn.h>
	])
], [
	ac_cv_have_decl_RTLD_DI_LINKMAP="no"
])

AM_CONDITIONAL([HAVE_DLINFO], [test "x${ac_cv_have_decl_RTLD_DI_LINKMAP}" = "xyes"])

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
]])], [
	AC_MSG_RESULT([yes])
], [
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([Please upgrade your version of liburcu to 0.6.6 or better])
])

# urcu - check that URCU lib is available to compilation
AC_CHECK_LIB([urcu-bp], [synchronize_rcu_bp], [], [AC_MSG_ERROR([Cannot find liburcu-bp lib. Use [LDFLAGS]=-Ldir to specify its location.])])

# urcu - check that URCU lib is at least version 0.6
AC_CHECK_LIB([urcu-bp], [call_rcu_bp], [], [AC_MSG_ERROR([liburcu 0.6 or newer is needed, please update your version or use [LDFLAGS]=-Ldir to specify the right location.])])

# numa.h integration
AS_IF([test "x$NO_NUMA" = "x1"],[
      AS_IF([test "x$enable_numa" = "x" ], [enable_numa=no])
])

AC_ARG_ENABLE([numa], [
AS_HELP_STRING([--disable-numa], [disable NUMA support])
], [
	enable_numa=$enableval
], [
	enable_numa=yes
])

AS_IF([test "x$enable_numa" = "xyes"], [
	# numa - check that numa lib is available
	AC_CHECK_LIB([numa], [numa_available], [],
[AC_MSG_ERROR([libnuma is not available. Please either install it (e.g. libnuma-dev) or use [LDFLAGS]=-Ldir to specify the right location, or use --disable-numa configure argument to disable NUMA support.])])
	have_libnuma=yes
])
AM_CONDITIONAL([HAVE_LIBNUMA], [test "x$have_libnuma" = "xyes"])

# optional linux/perf_event.h
AC_CHECK_HEADERS([linux/perf_event.h], [have_perf_event=yes], [])

# Perf event counters are supported on all architectures supported by
# perf, using the read system call as fallback.
AM_CONDITIONAL([HAVE_PERF_EVENT], [test "x$have_perf_event" = "xyes"])

AS_IF([test "x$have_perf_event" = "xyes"], [
	AC_DEFINE([LTTNG_UST_HAVE_PERF_EVENT], [1])
])

AS_IF([test "x$NO_UNALIGNED_ACCESS" = "x"], [
	AC_DEFINE([LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS], [1])
])

# Check for JNI header files if requested
AC_ARG_ENABLE([jni-interface], [
AS_HELP_STRING([--enable-jni-interface], [build JNI interface between C and Java. Needs Java include files [default=no]])
], [
	jni_interface=$enableval
], [
	jni_interface=no
])

AM_CONDITIONAL([BUILD_JNI_INTERFACE], [test "x$jni_interface" = "xyes"])


AC_ARG_ENABLE([java-agent-jul], [
AS_HELP_STRING([--enable-java-agent-jul], [build the LTTng UST Java agent with JUL support [default=no]])
], [
	java_agent_jul=$enableval
], [
	java_agent_jul=no
])

AC_ARG_ENABLE([java-agent-log4j], [
AS_HELP_STRING([--enable-java-agent-log4j], [build the LTTng UST Java agent with Log4j support [default=no]])
], [
	java_agent_log4j=$enableval
], [
	java_agent_log4j=no
])

AC_ARG_ENABLE([java-agent-all], [
AS_HELP_STRING([--enable-java-agent-all], [build the LTTng UST Java agent with all supported backends [default=no]])
], [
	java_agent_jul=$enableval
	java_agent_log4j=$enableval
], [:])

AM_CONDITIONAL([BUILD_JAVA_AGENT], [test "x$java_agent_jul" = "xyes" || test "x$java_agent_log4j" = "xyes"])
AM_CONDITIONAL([BUILD_JAVA_AGENT_WITH_JUL], [test "x$java_agent_jul" = "xyes"])
AM_CONDITIONAL([BUILD_JAVA_AGENT_WITH_LOG4J], [test "x$java_agent_log4j" = "xyes"])

AS_IF([test "x$jni_interface" = "xyes" || test "x$java_agent_jul" = "xyes" || test "x$java_agent_log4j" = "xyes"], [
	AX_JAVA_OPTIONS
	AX_PROG_JAVAC
	AX_PROG_JAVA
	AX_PROG_JAR

	AX_JNI_INCLUDE_DIR
	for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
	do
		JNI_CPPFLAGS="$JNI_CPPFLAGS -I$JNI_INCLUDE_DIR"
	done

	saved_CPPFLAGS="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $JNI_CPPFLAGS"
	AX_PROG_JAVAH
	CPPFLAGS="$saved_CPPFLAGS"
])

AS_IF([test "x$java_agent_log4j" = "xyes"], [
	AX_CHECK_CLASSPATH
	AX_CHECK_CLASS([org.apache.log4j.Logger])
	AS_IF([test "x$ac_cv_class_org_apache_log4j_Logger" = "xno"], [
		AC_MSG_ERROR([The UST Java agent support for log4j was requested but the Log4j classes were not found. Please specify the location of the Log4j jar via the Java CLASSPATH e.g: export CLASSPATH="/path/to/log4j.jar"])
	])
])

# Option to build the python agent
AC_ARG_ENABLE([python-agent], [
AS_HELP_STRING([--enable-python-agent], [build the LTTng UST Python agent [default=no]])
], [
	python_agent=$enableval
], [:])
AM_CONDITIONAL([BUILD_PYTHON_AGENT], [test "x$python_agent" = "xyes"])
AS_IF([test "x$python_agent" = "xyes"], [
	AM_PATH_PYTHON([2.7])
])

# sdt.h integration
AC_ARG_WITH([sdt], [
AS_HELP_STRING([--with-sdt], [provide SystemTap integration via sdt.h [default=no]])
], [
	with_sdt=$withval
], [
	with_sdt="no"
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
		AC_DEFINE([LTTNG_UST_HAVE_SDT_INTEGRATION], [1])
	], [
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([The sdt.h integration was requested but the STAP_PROBEV define cannot be used. Make sure it is installed, and up to date, or use CPPFLAGS=-I/path/ to specify a non-standard path to sys/sdt.h])
	])
])

AC_ARG_WITH([lttng-system-rundir], [
AS_HELP_STRING([--with-lttng-system-rundir], [Location of the system directory where LTTng-UST expects the system-wide lttng-sessiond runtime files. The default is "/var/run/lttng".]),
], [
	lttng_system_rundir="$withval"
], [
	lttng_system_rundir="/var/run/lttng"
])
AC_DEFINE_UNQUOTED([LTTNG_SYSTEM_RUNDIR], ["$lttng_system_rundir"],
		[LTTng system runtime directory])

AC_CHECK_PROG([BUILD_GEN_TP_EXAMPLES], [python], ["yes"])
AM_CONDITIONAL([BUILD_GEN_TP_EXAMPLES], [test "x$BUILD_GEN_TP_EXAMPLES" = "xyes"])

# Enable building examples
AC_ARG_ENABLE(
	examples,
	AS_HELP_STRING(
		[--disable-examples],
		[Do not build and install examples]
	),
	[enable_examples=$enableval],
	[enable_examples=yes]
)

AM_CONDITIONAL([ENABLE_EXAMPLES], [test "x$enable_examples" != "xno"])

# Set $IN_GIT_REPO if we're in the Git repository; the `bootstrap` file
# is not distributed in tarballs.
AS_IF([test -f "$srcdir/bootstrap"], [in_git_repo=yes], [in_git_repo=no])
AM_CONDITIONAL([IN_GIT_REPO], [test "x$in_git_repo" = "xyes"])

# Enable building man pages (user's intention).
AC_ARG_ENABLE(
	man-pages,
	AS_HELP_STRING(
		[--disable-man-pages],
		[Do not build and install man pages (already built in a distributed tarball)]
	),
	[man_pages_opt=$enableval],
	[man_pages_opt=yes]
)

# Check for asciidoc and xmlto if we enabled building the man pages.
have_asciidoc_xmlto=no
warn_prebuilt_man_pages=no

AS_IF([test "x$man_pages_opt" = "xyes"], [
	AC_PATH_PROG([ASCIIDOC], [asciidoc], [no])
	AC_PATH_PROG([XMLTO], [xmlto], [no])

	AS_IF([test "x$ASCIIDOC" = "xno" || test "x$XMLTO" = "xno"], [
		AS_IF([test "x$in_git_repo" = "xyes"], [
			# This is an error because we're in the Git repo, which
			# means the man pages are not already generated for us,
			# thus asciidoc/xmlto are required because we were asked
			# to build the man pages.
			AC_MSG_ERROR([
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

# Export man page build condition: build the man pages if the user
# asked for it, and if the tools are available.
AM_CONDITIONAL([MAN_PAGES_OPT], [test "x$man_pages_opt" != "xno"])
AM_CONDITIONAL([HAVE_ASCIIDOC_XMLTO], [test "x$have_asciidoc_xmlto" = "xyes"])

# Default values
AC_DEFUN([_AC_DEFINE_AND_SUBST], [
	AC_DEFINE_UNQUOTED([CONFIG_$1], [$2], [$1])
	$1="$2"
	AC_SUBST([$1])
])

_AC_DEFINE_AND_SUBST([LTTNG_UST_DEFAULT_CONSTRUCTOR_TIMEOUT_MS], [3000])

AM_CFLAGS="-Wall"
AC_SUBST(AM_CFLAGS)
AC_SUBST(JNI_CPPFLAGS)

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/examples/Makefile
	doc/man/Makefile
	include/Makefile
	include/lttng/ust-version.h
	snprintf/Makefile
	libringbuffer/Makefile
	liblttng-ust-comm/Makefile
	liblttng-ust/Makefile
	liblttng-ust-ctl/Makefile
	liblttng-ust-fork/Makefile
	liblttng-ust-dl/Makefile
	liblttng-ust-fd/Makefile
	liblttng-ust-java/Makefile
	liblttng-ust-java-agent/Makefile
	liblttng-ust-java-agent/java/Makefile
	liblttng-ust-java-agent/java/lttng-ust-agent-all/Makefile
	liblttng-ust-java-agent/java/lttng-ust-agent-common/Makefile
	liblttng-ust-java-agent/java/lttng-ust-agent-jul/Makefile
	liblttng-ust-java-agent/java/lttng-ust-agent-log4j/Makefile
	liblttng-ust-java-agent/jni/Makefile
	liblttng-ust-java-agent/jni/common/Makefile
	liblttng-ust-java-agent/jni/jul/Makefile
	liblttng-ust-java-agent/jni/log4j/Makefile
	liblttng-ust-libc-wrapper/Makefile
	liblttng-ust-cyg-profile/Makefile
	liblttng-ust-python-agent/Makefile
	python-lttngust/Makefile
	python-lttngust/setup.py
	python-lttngust/lttngust/__init__.py
	tools/Makefile
	tests/Makefile
	tests/ctf-types/Makefile
	tests/hello/Makefile
	tests/hello.cxx/Makefile
	tests/same_line_tracepoint/Makefile
	tests/snprintf/Makefile
	tests/ust-elf/Makefile
	tests/benchmark/Makefile
	tests/utils/Makefile
	tests/test-app-ctx/Makefile
	tests/gcc-weak-hidden/Makefile
	lttng-ust.pc
])

# Create link for python agent for the VPATH guru.
AC_CONFIG_LINKS([
	python-lttngust/lttngust/agent.py:python-lttngust/lttngust/agent.py
	python-lttngust/lttngust/cmd.py:python-lttngust/lttngust/cmd.py
	python-lttngust/lttngust/debug.py:python-lttngust/lttngust/debug.py
	python-lttngust/lttngust/loghandler.py:python-lttngust/lttngust/loghandler.py
])

AC_OUTPUT


#
# Mini-report on what will be built.
#

PPRINT_INIT
PPRINT_SET_INDENT(1)
PPRINT_SET_TS(38)

AS_ECHO
AS_ECHO("${PPRINT_COLOR_BLDBLU}LTTng-ust $PACKAGE_VERSION \"V_NAME\"$PPRINT_COLOR_RST")
AS_ECHO

AS_ECHO("V_DESC")

AS_ECHO
PPRINT_SUBTITLE([System])

PPRINT_PROP_STRING([Target architecture], $host_cpu)

test "x$NO_UNALIGNED_ACCESS" != "x1" && value=1 || value=0
PPRINT_PROP_BOOL([Efficient unaligned memory access], $value)

AS_IF([test "x$UNSUPPORTED_ARCH" = "x1"],[
       PPRINT_WARN([Your architecture ($host_cpu) is unsupported, using safe default of no unaligned access.])
])

AS_ECHO
PPRINT_SUBTITLE([Features])
PPRINT_SET_INDENT(1)

test "x$with_sdt" = "xyes" && value=1 || value=0
PPRINT_PROP_BOOL_CUSTOM([sdt.h integration], $value, [use --with-sdt])

test "x$java_agent_jul" = xyes && value=1 || value=0
PPRINT_PROP_BOOL_CUSTOM([Java agent (JUL support)], $value, [use --enable-java-agent-jul])

test "x$java_agent_log4j" = xyes && value=1 || value=0
PPRINT_PROP_BOOL_CUSTOM([Java agent (Log4j support)], $value, [use --enable-java-agent-log4j])

test "x$jni_interface" = xyes && value=1 || value=0
PPRINT_PROP_BOOL_CUSTOM([JNI interface (JNI)], $value, [use --enable-jni-interface])

test "x$python_agent" = xyes && value=1 || value=0
PPRINT_PROP_BOOL_CUSTOM([Python agent], $value, [use --enable-python-agent])

test "x$enable_numa" = xyes && value=1 || value=0
PPRINT_PROP_BOOL([NUMA], $value)

AS_ECHO
PPRINT_SET_INDENT(0)

test "x$enable_examples" = xyes && value=1 || value=0
PPRINT_PROP_BOOL([Build and install examples], $value, $PPRINT_COLOR_SUBTITLE)

# man pages build enabled/disabled
m4_pushdef([build_man_pages_msg], [Build and install man pages])

AS_IF([test "x$man_pages_opt" != "xno"], [
	AS_IF([test "x$in_git_repo" = "xyes"], [
		PPRINT_PROP_BOOL([build_man_pages_msg], 1, $PPRINT_COLOR_SUBTITLE)
	], [
		AS_IF([test "x$have_asciidoc_xmlto" = "xyes"], [
			PPRINT_PROP_BOOL([build_man_pages_msg], 1, $PPRINT_COLOR_SUBTITLE)
		], [
			PPRINT_PROP_STRING([build_man_pages_msg],
				[${PPRINT_COLOR_BLDGRN}yes (already built)],
				$PPRINT_COLOR_SUBTITLE)
		])
	])
], [
	PPRINT_PROP_BOOL([build_man_pages_msg], 0, $PPRINT_COLOR_SUBTITLE)
])

m4_popdef([build_man_pages_msg])

PPRINT_SET_INDENT(1)

report_bindir="`eval eval echo $bindir`"
report_libdir="`eval eval echo $libdir`"

# Print the bindir and libdir this `make install' will install into.
AS_ECHO
PPRINT_SUBTITLE([Install directories])
PPRINT_PROP_STRING([Binaries], [$report_bindir])
PPRINT_PROP_STRING([Libraries], [$report_libdir])

AS_ECHO
PPRINT_SUBTITLE([System directories])

PPRINT_PROP_STRING([lttng-sessiond rundir], [$lttng_system_rundir])

PPRINT_SET_INDENT(0)

AS_IF([test "x$warn_prebuilt_man_pages" = "xyes" ], [
	AS_ECHO
	PPRINT_WARN([Both asciidoc and xmlto are needed to build the LTTng-UST man pages.

Note that the man pages are already built in this distribution tarball,
therefore asciidoc and xmlto are only needed if you intend to modify
their sources.

Use --disable-man-pages to completely disable building and installing
the man pages.])
])
