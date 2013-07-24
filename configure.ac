#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([lttng-ust],[2.3.0-rc1],[mathieu dot desnoyers at efficios dot com])

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
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([include/lttng/tracepoint.h])

# Configuration options, which will be installed in the config.h
AC_CONFIG_HEADERS([config.h include/lttng/ust-config.h])
AH_TEMPLATE([LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS], [Use efficient unaligned access.])
AH_TEMPLATE([LTTNG_UST_HAVE_SDT_INTEGRATION], [SystemTap integration via sdt.h])

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

version_name="Dominus Vobiscum"
version_description="A very succulent line-up of beers brewed at Microbrasserie Charlevoix. Elaborated starting from special malts and fermented with a Belgian yeast. These beers are refermented in bottle and will make you discover the richness of wheat, amber and triple styles."

AC_DEFINE_UNQUOTED([VERSION_NAME], ["$version_name"], [UST version name])
AC_DEFINE_UNQUOTED([VERSION_DESCRIPTION], ["$version_description"], [UST version description])

AC_PROG_GREP
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
	powerpc64) ;;
	s390) NO_UNALIGNED_ACCESS=1 ;;
	s390x) NO_UNALIGNED_ACCESS=1 ;;
        arm*) NO_UNALIGNED_ACCESS=1 ;;
	mips*) NO_UNALIGNED_ACCESS=1 ;;
	tile*) NO_UNALIGNED_ACCESS=1 ;;
	*) AC_MSG_ERROR([unable to detect alignment requirements (unsupported architecture ($host_cpu)?)]) ;;
esac

if test x$NO_UNALIGNED_ACCESS = x ; then
AC_DEFINE([LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS], [1])
fi

# Set compile flags to java include files if given
AC_ARG_WITH([java-jdk],
	[AS_HELP_STRING([--with-java-jdk=DIR],[use the Java JDK in DIR. Ex : $JAVA_HOME.])],
	[JAVA_JDK=$withval],
	[JAVA_JDK=""]
)
AS_IF([test $JAVA_JDK],[
	AS_IF([test -d $JAVA_JDK],[
                AC_MSG_RESULT([using Java includes in $JAVA_SDK])
                SUBDIRS=`find $JAVA_JDK/include -type d`
		CPPFLAGS+=" "
                CPPFLAGS+=`for x in $SUBDIRS; do echo -n "-I$x "; done`
		CPPFLAGS+=" "
        ],[
                AC_MSG_ERROR(Unable to find Java include files in $JAVA_JDK)
        ])
])

# Check for JNI header files if requested
AC_ARG_WITH([jni-interface],
	[AS_HELP_STRING([--with-jni-interface],[build JNI interface between C and Java. Needs Java include files [default=no]])],
	[jni_interface=$withval],
	[jni_interface=no]
)

AS_IF([test "x$jni_interface" = "xyes"],[
        AC_CHECK_HEADERS([jni.h],[],[
        AC_MSG_ERROR([missing jni.h
Make sure Sun Java, OpenJDK or GCJ is installed and that this header file exists in the system path.
Use the --with-java-jdk=DIR flag to point to your Java include files, or disable the JNI interface.])
	])
])
AM_CONDITIONAL([BUILD_JNI_INTERFACE], [test "x$jni_interface" = "xyes"])

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
	liblttng-ust-java/Makefile
	liblttng-ust-libc-wrapper/Makefile
	liblttng-ust-cyg-profile/Makefile
	tools/Makefile
	tests/Makefile
	tests/hello/Makefile
	tests/hello.cxx/Makefile
	tests/same_line_tracepoint/Makefile
	tests/snprintf/Makefile
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
AS_ECHO_N("Java support (JNI): ")
AS_IF([test "x$jni_interface" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO_N("sdt.h integration:  ")
AS_IF([test "x$with_sdt" = "xyes"], [AS_ECHO("Enabled")], [AS_ECHO("Disabled")])

AS_ECHO()
AS_ECHO("Type 'make' to compile.")

