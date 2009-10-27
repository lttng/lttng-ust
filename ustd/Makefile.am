AM_CPPFLAGS = -I$(top_srcdir)/libust -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/include

bin_PROGRAMS = ustd
ustd_SOURCES = lowlevel.c ustd.c ustd.h $(top_srcdir)/libustcomm/ustcomm.c $(top_srcdir)/libustcomm/ustcomm.h
ustd_LDFLAGS = -lpthread
ustd_CFLAGS = -DUST_COMPONENT=ustd
