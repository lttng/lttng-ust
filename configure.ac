#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.63])
AC_INIT([ust], [0.0], [pierre-marc dot fournier at polymtl dot ca])
AC_CONFIG_AUX_DIR(make_scripts)
AM_INIT_AUTOMAKE([0.0 foreign])
AC_CONFIG_SRCDIR([ust/localerr.h])
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

AC_ARG_WITH(urcu, [  --with-urcu path	Path to userspace RCU source], URCU_PATH="$withval", AC_MSG_ERROR([Must specify urcu path.]))
AC_CHECK_FILE("$URCU_PATH/urcu.h", , AC_MSG_ERROR([Cannot find urcu.h in urcu directory]))
AC_ARG_WITH(kcompat, [  --with-kcompat path	Path to userspace kcompat source], KCOMPAT_PATH="$withval", AC_MSG_ERROR([Must specify kcompat path.]))
AC_CHECK_FILE("$KCOMPAT_PATH/kcompat.h", , AC_MSG_ERROR([Cannot find kcompat.h in kcompat directory]))
AC_SUBST(URCU_PATH)
AC_SUBST(KCOMPAT_PATH)

#AC_CONFIG_FILES([Makefile
#                 hello/Makefile
#                 libmallocwrap/Makefile
#                 libmarkers/Makefile
#                 libtracectl/Makefile
#                 libtracing/Makefile
#                 ust/Makefile
#                 ustd/Makefile])

AC_CONFIG_FILES([Makefile libust/Makefile hello/Makefile libmallocwrap/Makefile ustd/Makefile ust/Makefile])
AC_OUTPUT
