AM_CPPFLAGS = -I$(top_srcdir)/libust -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/include -I$(top_srcdir)/libustconsumer
AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ust-consumerd

ust_consumerd_SOURCES = ust-consumerd.c

ust_consumerd_LDADD = \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la \
	$(top_builddir)/libustconsumer/libustconsumer.la

ust_consumerd_CFLAGS = -DUST_COMPONENT=ust-consumerd -fno-strict-aliasing
