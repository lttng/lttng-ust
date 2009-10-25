#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.63])
AC_INIT([ust], [0.0], [pierre-marc dot fournier at polymtl dot ca])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([0.0 foreign dist-bzip2 no-dist-gzip])
AC_CONFIG_SRCDIR([ustctl/ustctl.c])
AC_CONFIG_HEADERS([config.h])

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

# URCU

# urcu - check if we just find the headers it out of the box.
AC_CHECK_HEADERS([urcu-bp.h], [], [AC_MSG_ERROR([Cannot find [URCU] headers (urcu-bp.h). Use [CFLAGS]=-Idir to specify their location.])])

# urcu - check that URCU lib is available to compilation
AC_CHECK_LIB([urcu-bp], [synchronize_rcu], [], [AC_MSG_ERROR([Cannot find liburcu-bp lib. Use [LDFLAGS]=-Ldir to specify its location.])])

# kcompat

AC_CHECK_HEADERS([kcompat.h], [], [AC_MSG_ERROR([Cannot find kcompat headers (kcompat.h). Use [CFLAGS]=-Idir to specify their location.])])


AC_CONFIG_FILES([
	Makefile
	include/Makefile
	libust/Makefile
	tests/Makefile
	tests/hello/Makefile
	tests/hello2/Makefile
	tests/basic/Makefile
	tests/basic_long/Makefile
	tests/fork/Makefile
	libmallocwrap/Makefile
	libinterfork/Makefile
	ustd/Makefile
	ustctl/Makefile
])
AC_OUTPUT
