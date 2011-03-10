AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustfork.la
libustfork_la_SOURCES = ustfork.c
libustfork_la_LIBADD = \
	-ldl \
	$(top_builddir)/libust/libust.la
libustfork_CFLAGS = -DUST_COMPONENT=libustfork -fno-strict-aliasing
