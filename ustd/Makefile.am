AM_CPPFLAGS = -I$(top_srcdir)/libust -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/include -I$(top_srcdir)/libustd
AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ustd

ustd_SOURCES = ustd.c

ustd_LDADD = \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la \
	$(top_builddir)/libustd/libustd.la

ustd_CFLAGS = -DUST_COMPONENT=ustd -fno-strict-aliasing
