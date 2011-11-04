#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([lttng-ust], [1.9.0], [mathieu dot desnoyers at efficios dot com])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([include/lttng/tracepoint.h])
AC_CONFIG_HEADERS([config.h include/lttng/config.h])
AH_TEMPLATE([HAVE_EFFICIENT_UNALIGNED_ACCESS], [Use efficient unaligned access.])
# Compute minor/major version numbers
major_version=`echo AC_PACKAGE_VERSION | sed 's/\..*//'`
minor_version=`echo AC_PACKAGE_VERSION | sed 's/.*\.//' | sed 's/^0//'`
AC_SUBST([MAJOR_VERSION], [$major_version])
AC_SUBST([MINOR_VERSION], [$minor_version])
AC_DEFINE_UNQUOTED([VERSION_MAJOR], $major_version, [UST major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], $minor_version, [UST minor version number])


# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

## Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([pthread], [pthread_create])

# Check for libuuid
AC_CHECK_LIB([uuid], [uuid_generate], [],
	[AC_MSG_ERROR([Cannot find libuuid. Use [LDFLAGS]=-Ldir to specify its location.])]
)

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
AC_CHECK_FUNCS([gettimeofday munmap socket strerror strtol])

CFLAGS="-Wall $CFLAGS"

# URCU

# urcu - check if we just find the headers it out of the box.
AC_CHECK_HEADERS([urcu-bp.h], [], [AC_MSG_ERROR([Cannot find [URCU] headers (urcu-bp.h). Use [CFLAGS]=-Idir to specify their location.
This error can also occur when the liburcu package's configure script has not been run.])])

AC_MSG_CHECKING([caa_likely()])
AC_TRY_COMPILE(
[
#include <urcu/compiler.h>
],
[
void fct(void)
{
	if (caa_likely(1)) {
	}
}
],
[
	AC_MSG_RESULT([yes])
],
[
	AC_MSG_RESULT([no])
	AC_MSG_ERROR([Please upgrade your version of liburcu to 0.6.6 or better])
]
)

# urcu - check that URCU lib is available to compilation
AC_CHECK_LIB([urcu-bp], [synchronize_rcu_bp], [], [AC_MSG_ERROR([Cannot find liburcu-bp lib. Use [LDFLAGS]=-Ldir to specify its location.])])

# urcu - check that URCU lib is at least version 0.6
AC_CHECK_LIB([urcu-bp], [call_rcu_bp], [], [AC_MSG_ERROR([liburcu 0.6 or newer is needed, please update your version or use [LDFLAGS]=-Ldir to specify the right location.])])


# Check for various supplementary host information (beyond the
# triplet) which might affect the library format choices.  E.g., we
# can be building with `i686-unknown-linux-gnu-gcc -m64'

case "${host}" in
changequote(,)dnl
  i[34567]86-*-linux*)
changequote([,])dnl
    AC_CACHE_CHECK([if building for x86-64], [ust_cv_i386_is_x86_64],
                    [save_CPPFLAGS="$CPPFLAGS"
                    CPPFLAGS="$CPPFLAGS $CFLAGS"
                    AC_EGREP_CPP([got it], [
#if __x86_64__
got it
#endif
                 ], [ust_cv_i386_is_x86_64=yes],
                    [ust_cv_i386_is_x86_64=no])
                    CPPFLAGS="$save_CPPFLAGS"])
    ;;
esac

AC_MSG_CHECKING([library format for the host system])
case $host_cpu in
changequote(,)dnl
	i[3456]86)
changequote([,])dnl
	  if test "$ust_cv_i386_is_x86_64" = yes ; then
	     LIBFORMAT="elf64-x86-64"
	  else
	     LIBFORMAT="elf32-i386"
	  fi
	  ;;
	x86_64) LIBFORMAT="elf64-x86-64" ;;
	powerpc) LIBFORMAT="elf32-powerpc" ;;
	ppc64) LIBFORMAT="elf64-powerpc" ;;
	powerpc64) LIBFORMAT="elf64-powerpc" ;;
	s390) LIBFORMAT="elf32-s390"; NO_UNALIGNED_ACCESS=1 ;;
	s390x) LIBFORMAT="elf64-s390"; NO_UNALIGNED_ACCESS=1 ;;
        armv5) LIBFORMAT="elf32-littlearm"; NO_UNALIGNED_ACCESS=1 ;;
	arm) LIBFORMAT="elf32-littlearm"; NO_UNALIGNED_ACCESS=1 ;;
	mips*) LIBFORMAT=""; NO_UNALIGNED_ACCESS=1;;
	*) AC_MSG_ERROR([unable to detect library format (unsupported architecture ($host_cpu)?)]) ;;
esac
AC_SUBST(LIBFORMAT)
AC_MSG_RESULT($LIBFORMAT)

if test "x$host_cpu" = "xarm" ; then
AC_MSG_CHECKING([checking for armv5])
AC_TRY_COMPILE(
[
],
[
#ifndef __ARM_ARCH_5TEJ__
#error "no arm5 here"
#endif
],
[
	AC_MSG_RESULT([yes])
	NO_UNALIGNED_ACCESS=1
]
,
[
	AC_MSG_RESULT([no])
]
)
fi
if test x$NO_UNALIGNED_ACCESS = x ; then
AC_DEFINE([HAVE_EFFICIENT_UNALIGNED_ACCESS], [1])
fi

# Set compile flags to java include files if given
AC_ARG_WITH(java_jdk, [  --with-java-jdk=DIR     use java jdk from DIR. Ex : $JAVA_HOME.], JAVA_SDK=$withval,)
if test $JAVA_SDK; then
        if test -d $JAVA_SDK; then
                AC_MSG_RESULT([using java include in $JAVA_SDK])
                SUBDIRS=`find $JAVA_SDK/include -type d`
		CFLAGS+=" "
                CFLAGS+=`for x in $SUBDIRS; do echo -n "-I$x "; done`
		CFLAGS+=" "
        else
                AC_MSG_ERROR(Unable to find java include file in $JAVA_JDK)
        fi
fi

# Check for JNI header files if requested
AC_ARG_WITH(jni-interface, [  --with-jni-interface    build JNI interface between C and java. Need java include files.
			  [[default=no]]])

if test -z "$with_jni_interface"; then
        with_jni_interface=${with_jni_interface_default-no}
fi

if test "$with_jni_interface" = "yes"; then
        AC_CHECK_HEADERS([jni.h],,AC_MSG_ERROR([
missing jni.h
Make sure Sun Java or OpenJDK or GCJ is installed and that this header file exists in the system path.
Use --with-java-jdk=DIR flag to point to your java include files or desactivate the JNI interface.]))
fi
AM_CONDITIONAL(BUILD_JNI_INTERFACE, test "$with_jni_interface" = "yes")

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	include/lttng/version.h
	doc/Makefile
	doc/man/Makefile
	doc/info/Makefile
	snprintf/Makefile
	libringbuffer/Makefile
	liblttng-ust-comm/Makefile
	liblttng-ust/Makefile
	liblttng-ust-ctl/Makefile
	liblttng-ust-fork/Makefile
	liblttng-ust-java/Makefile
	liblttng-ust-malloc/Makefile
	tests/Makefile
	tests/hello/Makefile
	tests/ust-basic-tracing/Makefile
	tests/ust-multi-test/Makefile
	tests/hello2/Makefile
	tests/basic/Makefile
	tests/basic_long/Makefile
	tests/fork/Makefile
	tests/simple_include/Makefile
	tests/snprintf/Makefile
	tests/test-nevents/Makefile
	tests/test-libustinstr-malloc/Makefile
	tests/dlopen/Makefile
	tests/same_line_marker/Makefile
	tests/trace_event/Makefile
	tests/tracepoint/Makefile
	tests/tracepoint/benchmark/Makefile
	tests/register_test/Makefile
	tests/libustctl_function_tests/Makefile
	tests/exit-fast/Makefile
	lttng-ust.pc
])
AC_OUTPUT
