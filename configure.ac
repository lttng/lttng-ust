#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([ust], [0.12], [nils dot carlson at ericsson dot com])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([config])
AM_INIT_AUTOMAKE([foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([ustctl/ustctl.c])
AC_CONFIG_HEADERS([config.h include/ust/config.h])
AH_TEMPLATE([HAVE_EFFICIENT_UNALIGNED_ACCESS], [Use efficient unaligned access.])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

## Checks for libraries.
## FIXME: Replace `main' with a function in `-ldl':
#AC_CHECK_LIB([dl], [main])
## FIXME: Replace `main' with a function in `-lmarkers':
#AC_CHECK_LIB([markers], [main])
## FIXME: Replace `main' with a function in `-lpthread':
#AC_CHECK_LIB([pthread], [main])
## FIXME: Replace `main' with a function in `-ltracectl':
#AC_CHECK_LIB([tracectl], [main])
## FIXME: Replace `main' with a function in `-ltracing':
#AC_CHECK_LIB([tracing], [main])
## FIXME: Replace `main' with a function in `-lurcu':
#AC_CHECK_LIB([urcu], [main])

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

# urcu - check that URCU lib is available to compilation
AC_CHECK_LIB([urcu-bp], [synchronize_rcu], [], [AC_MSG_ERROR([Cannot find liburcu-bp lib. Use [LDFLAGS]=-Ldir to specify its location.])])

# urcu - check that URCU lib is at least version 0.5.4
AC_CHECK_LIB([urcu-bp], [rcu_bp_before_fork], [], [AC_MSG_ERROR([liburcu 0.5.4 or newer is needed, please update your version or use [LDFLAGS]=-Ldir to specify the right location.])])

# urcu - check that URCU lib is at least version 0.5
AC_CHECK_DECL([cds_list_add(0, 0)], [], [AC_MSG_ERROR([liburcu 0.5 or newer is needed, please update your version or use [LDFLAGS]=-Ldir to specify the right location.])], [[#include <urcu/list.h>]])



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
	s390) LIBFORMAT="elf32-s390" ;;
	s390x) LIBFORMAT="elf64-s390" ;;
        armv5) LIBFORMAT="elf32-littlearm"; NO_UNALIGNED_ACCESS=1 ;;
	arm) LIBFORMAT="elf32-littlearm" ;;
	mips*) LIBFORMAT="" ;;
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

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/man/Makefile
	doc/info/Makefile
	include/Makefile
	libust/Makefile
	tests/Makefile
	tests/hello/Makefile
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
	libustinstr-malloc/Makefile
	libustfork/Makefile
	libustconsumer/Makefile
	ust-consumerd/Makefile
	ustctl/Makefile
	libustcomm/Makefile
	libustctl/Makefile
	snprintf/Makefile
])
AC_OUTPUT
