AM_CPPFLAGS = -I$(top_srcdir)/libust -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ustd

ustd_SOURCES = lowlevel.c ustd.c ustd.h

ustd_LDADD = \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la

ustd_LDFLAGS = -lpthread
ustd_CFLAGS = -DUST_COMPONENT=ustd -fno-strict-aliasing
