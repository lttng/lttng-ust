AM_CPPFLAGS = -I$(top_srcdir)/libust -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustconsumer.la

libustconsumer_la_SOURCES = libustconsumer.c lowlevel.c lowlevel.h

libustconsumer_la_LDFLAGS = -no-undefined -version-info 0:0:0

libustconsumer_la_LIBADD = \
	-lpthread \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la

libustconsumer_la_CFLAGS = -fno-strict-aliasing
