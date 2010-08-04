AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = libustcomm.la
libustcomm_la_SOURCES = \
	ustcomm.h \
	ustcomm.c \
	multipoll.h \
	multipoll.c
libustcomm_la_LDFLAGS = -no-undefined -static
libustcomm_la_CFLAGS = -DUST_COMPONENT="libustcomm" -fPIC -fno-strict-aliasing
