AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm

lib_LTLIBRARIES = libustsnprintf.la
libustsnprintf_la_SOURCES = \
	fflush.c \
	fileext.h \
	floatio.h \
	fvwrite.c \
	fvwrite.h \
	local.h \
	snprintf.c \
	various.h \
	vfprintf.c \
	wcio.h \
	wsetup.c
libustsnprintf_la_LDFLAGS = -no-undefined -version-info 0:0:0 -static
libustsnprintf_la_CFLAGS = -DUST_COMPONENT="ust_snprintf" -fPIC

check_PROGRAMS = prog
prog_SOURCES = prog.c
prog_LDADD = libustsnprintf.la
TESTS = prog
